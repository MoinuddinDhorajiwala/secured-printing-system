# app.py
import os
import io
import secrets
import qrcode
import re
from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file, make_response, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import psycopg2
import psycopg2.extras
from config import SECRET_KEY, UPLOAD_FOLDER, ALLOWED_EXTENSIONS, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET, RAZORPAY_WEBHOOK_SECRET, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET
from db import get_connection, dict_cursor
import razorpay
from main2 import add_watermark, extract_pages, print_pdf
from file_converter import convert_to_pdf, is_conversion_required, get_converted_pdf_path
import tempfile, datetime, time
from authlib.integrations.flask_client import OAuth
import json
from flask_session import Session
import random
from datetime import timedelta
import pytz
from email_utils import email_service, generate_otp, store_otp, verify_otp

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = SECRET_KEY

# Configure Flask sessions for OAuth state management
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'secure_printing_'
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # 1 hour session timeout

# Initialize Flask-Session
server_session = Session(app)

# Session validation middleware
@app.before_request
def validate_session():
    """Validate session and logout if expired"""
    if 'user_id' in session:
        # Check if session has last activity timestamp
        if 'last_activity' in session:
            last_activity = session['last_activity']
            current_time = datetime.datetime.utcnow()
            # Get the current UTC time

            # Check if session has expired (1 hour)
            if current_time - last_activity > timedelta(hours=1):
                # Session expired, clear it
                session.clear()
                flash("Your session has expired. Please login again.")
                return redirect(url_for('login'))
        
        # Update last activity timestamp
        session['last_activity'] = datetime.datetime.utcnow()
        session.permanent = True

# Postmark email service is imported from email_utils module
# Removed SMTP configuration and old email functions

# Make config available in templates
@app.context_processor
def inject_config():
    return dict(config={
        'RAZORPAY_KEY_ID': RAZORPAY_KEY_ID,
        'RAZORPAY_KEY_SECRET': RAZORPAY_KEY_SECRET
    })

# Timezone conversion filter
@app.template_filter('localtime')
def localtime_filter(dt):
    """Convert UTC datetime to local timezone"""
    if not dt:
        return None
    
    # Get local timezone offset
    import pytz
    from datetime import datetime
    
    # If dt is naive (no timezone info), assume it's UTC
    if dt.tzinfo is None:
        dt = pytz.UTC.localize(dt)
    
    # Convert to local timezone
    local_tz = pytz.timezone('Asia/Kolkata')  # IST timezone
    local_dt = dt.astimezone(local_tz)
    
    return local_dt

# Base64 encoding filter for images
@app.template_filter('b64encode')
def b64encode_filter(data):
    """Encode binary data to base64 string"""
    if not data:
        return ''
    import base64
    return base64.b64encode(data).decode('utf-8')

# Initialize OAuth
oauth = OAuth(app)

# Configure Google OAuth (only if credentials are provided)
google = None
if GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET:
    google = oauth.register(
        name='google',
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        access_token_url='https://accounts.google.com/o/oauth2/token',
        access_token_params=None,
        authorize_url='https://accounts.google.com/o/oauth2/auth',
        authorize_params=None,
        api_base_url='https://www.googleapis.com/oauth2/v1/',
        userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
        client_kwargs={'scope': 'email profile'},
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
    )

# Configure Microsoft OAuth (only if credentials are provided)
microsoft = None
if MICROSOFT_CLIENT_ID and MICROSOFT_CLIENT_SECRET:
    microsoft = oauth.register(
        name='microsoft',
        client_id=MICROSOFT_CLIENT_ID,
        client_secret=MICROSOFT_CLIENT_SECRET,
        access_token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
        access_token_params=None,
        authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        authorize_params=None,
        api_base_url='https://graph.microsoft.com/v1.0/',
        userinfo_endpoint='https://graph.microsoft.com/v1.0/me',
        client_kwargs={'scope': 'openid email profile'},
        server_metadata_url='https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration'
    )

# ---- utils ----
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.")
            return redirect(url_for("login"))
        conn = get_connection()
        cur = dict_cursor(conn)
        cur.execute("SELECT is_admin FROM users WHERE user_id=%s", (session["user_id"],))
        row = cur.fetchone()
        cur.close(); conn.close()

        if not row or not row.get("is_admin"):
            flash("Admin access required.")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapper

# Download temporary document
@app.route("/download_temp_document/<int:temp_doc_id>")
@login_required
def download_temp_document(temp_doc_id):
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("""SELECT original_name, doc_blob, doc_type 
                    FROM temp_documents 
                    WHERE temp_doc_id=%s AND user_id=%s""", 
                (temp_doc_id, uid))
    row = cur.fetchone()
    cur.close(); conn.close()
    
    if not row:
        flash("Document not found or access denied.")
        return redirect(url_for("previously_printed"))
    
    data = row["doc_blob"]
    mime = row["doc_type"] or "application/pdf"
    filename = row["original_name"]
    
    # Convert memoryview to bytes if needed
    if isinstance(data, memoryview):
        data = data.tobytes()
    
    # Create response for download
    resp = make_response(data)
    resp.headers.set("Content-Type", mime)
    resp.headers.set("Content-Disposition", f"attachment; filename*=UTF-8''{filename}")
    return resp

# ----- routes -----
@app.route("/")
def index():
    return render_template("index.html")

# Registration (manual)
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")

        if not email.endswith("@mhssce.ac.in"):
            flash("Please signup with your mhssce.ac.in email only.")
            return redirect(url_for("register"))
            
        # Check if email already exists
        conn = get_connection()
        cur = dict_cursor(conn)
        try:
            cur.execute("SELECT user_id FROM users WHERE user_email = %s", (email,))
            if cur.fetchone():
                flash("Email already registered. Please login or use a different email.")
                return redirect(url_for("register"))
                
            # Create new user
            hashed_password = generate_password_hash(password)
            cur.execute(
                "INSERT INTO users (user_email, user_name, user_password) VALUES (%s, %s, %s)",
                (email, name, hashed_password)
            )
            conn.commit()
            
            flash("Registration successful! Please login.")
            return redirect(url_for("login"))
            
        except Exception as e:
            flash(f"Registration failed: {str(e)}")
            return redirect(url_for("register"))
        finally:
            cur.close()
            conn.close()
    
    # For GET request
    return render_template("register.html")

# Forgot Password Routes
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Handle forgot password requests"""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        
        if not email:
            flash("Please enter your email address.")
            return redirect(url_for("forgot_password"))
        
        # Check if user exists
        conn = get_connection()
        cur = dict_cursor(conn)
        try:
            cur.execute("SELECT user_id, user_name FROM users WHERE user_email = %s", (email,))
            user = cur.fetchone()
            
            if not user:
                flash("No account found with that email address.")
                return redirect(url_for("forgot_password"))
            
            # Generate and send OTP
            otp = generate_otp()
            store_otp(email, otp)
            
            if email_service.send_otp_email(email, otp, "password_reset"):
                # Store email in session for reset process
                session['reset_password_email'] = email
                session['reset_user_name'] = user['user_name']
                flash("Password reset code has been sent to your email.")
                return redirect(url_for("reset_password"))
            else:
                flash("Failed to send reset code. Please try again.")
                return redirect(url_for("forgot_password"))
                
        except Exception as e:
            flash(f"Error processing request: {str(e)}")
            return redirect(url_for("forgot_password"))
        finally:
            cur.close(); conn.close()
    
    return render_template("forgot_password.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """Handle password reset with OTP"""
    if 'reset_password_email' not in session:
        flash("Please start the password reset process again.")
        return redirect(url_for("forgot_password"))
    
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        
        email = session['reset_password_email']
        
        # Validate inputs
        if not otp or not new_password or not confirm_password:
            flash("Please fill in all fields.")
            return redirect(url_for("reset_password"))
        
        if new_password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("reset_password"))
        
        if len(new_password) < 6:
            flash("Password must be at least 6 characters long.")
            return redirect(url_for("reset_password"))
        
        # Verify OTP
        if verify_otp(email, otp):
            # Update password
            conn = get_connection()
            cur = dict_cursor(conn)
            try:
                hashed_password = generate_password_hash(new_password)
                cur.execute("UPDATE users SET user_password = %s WHERE user_email = %s", 
                           (hashed_password, email))
                conn.commit()
                
                # Clear session data
                session.pop('reset_password_email', None)
                session.pop('reset_user_name', None)
                
                flash("Password has been reset successfully. Please login with your new password.")
                return redirect(url_for("login"))
                
            except Exception as e:
                conn.rollback()
                flash(f"Error resetting password: {str(e)}")
                return redirect(url_for("reset_password"))
            finally:
                cur.close(); conn.close()
        else:
            flash("Invalid or expired verification code.")
            return redirect(url_for("reset_password"))
    
    return render_template("reset_password.html")

@app.route("/resend-reset-otp")
def resend_reset_otp():
    """Resend OTP for password reset"""
    if 'reset_password_email' not in session:
        flash("Please start the password reset process again.")
        return redirect(url_for("forgot_password"))
    
    email = session['reset_password_email']
    
    # Generate and send new OTP
    otp = generate_otp()
    store_otp(email, otp)
    
    if email_service.send_otp_email(email, otp, "password_reset"):
        flash("New reset code has been sent to your email.")
    else:
        flash("Failed to send reset code. Please try again.")
    
    return redirect(url_for("reset_password"))

        # Check if user already exists
    conn = get_connection()
    cur = dict_cursor(conn)
    try:
            cur.execute("SELECT user_id FROM users WHERE user_email=%s", (email,))
            if cur.fetchone():
                flash("Email already registered. Please login.")
                return redirect(url_for("login"))
    except Exception as e:
            flash("Error checking user: " + str(e))
            return redirect(url_for("register"))
    finally:
            cur.close(); conn.close()

        # Generate and send OTP
    otp = generate_otp()
    store_otp(email, otp)
        
    if email_service.send_otp_email(email, otp):
            # Store registration data in session temporarily
            session['pending_registration'] = {
                'email': email,
                'name': name,
                'password': generate_password_hash(password),
                'provider': 'manual'
            }
            flash("OTP sent to your email. Please verify to complete registration.")
            return redirect(url_for('verify_registration_otp'))
    else:
            flash("Failed to send OTP. Please try again.")
            return redirect(url_for("register"))
    
    return render_template("register.html")

# OTP Verification for Registration
@app.route("/verify-registration-otp", methods=["GET", "POST"])
def verify_registration_otp():
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        
        if 'pending_registration' not in session:
            flash("Registration session expired. Please register again.")
            return redirect(url_for("register"))
        
        email = session['pending_registration']['email']
        
        if verify_otp(email, otp):
            # OTP verified, create user
            conn = get_connection()
            cur = dict_cursor(conn)
            try:
                cur.execute(
                    "INSERT INTO users (user_email, user_name, password) VALUES (%s,%s,%s) RETURNING user_id",
                    (session['pending_registration']['email'], 
                     session['pending_registration']['name'], 
                     session['pending_registration']['password'])
                )
                uid = cur.fetchone()["user_id"]
                conn.commit()
                
                # Clear pending registration
                session.pop('pending_registration', None)
                
                flash("Registration successful! Please log in.")
                return redirect(url_for("login"))
            except Exception as e:
                conn.rollback()
                flash("Registration error: " + str(e))
                return redirect(url_for("register"))
            finally:
                cur.close(); conn.close()
        else:
            flash("Invalid or expired OTP. Please try again.")
            return redirect(url_for("verify_registration_otp"))
    
    return render_template("verify_otp.html")

# Resend OTP
@app.route("/resend-otp")
def resend_otp():
    """Resend OTP for pending registration"""
    email = None
    
    # Check for pending registration types
    if 'pending_registration' in session:
        email = session['pending_registration']['email']
    elif 'pending_oauth_registration' in session:
        email = session['pending_oauth_registration']['email']
    
    if email:
        # Generate new OTP and send
        otp = generate_otp()
        store_otp(email, otp)
        
        if email_service.send_otp_email(email, otp):
            flash("New OTP sent to your email.")
        else:
            flash("Failed to send OTP. Please try again.")
    else:
        flash("No pending registration found.")
        return redirect(url_for("register"))
    
    # Redirect back to appropriate verification page
    if 'pending_registration' in session:
        return redirect(url_for('verify_registration_otp'))
    elif 'pending_oauth_registration' in session:
        return redirect(url_for('verify_oauth_otp'))
    else:
        return redirect(url_for("register"))

# OTP Verification for OAuth Registration
@app.route("/verify-oauth-otp", methods=["GET", "POST"])
def verify_oauth_otp():
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        
        if 'pending_oauth_registration' not in session:
            flash("Registration session expired. Please try again.")
            return redirect(url_for("login"))
        
        email = session['pending_oauth_registration']['email']
        
        if verify_otp(email, otp):
            # OTP verified, create user
            conn = get_connection()
            cur = dict_cursor(conn)
            try:
                cur.execute(
                    "INSERT INTO users (user_email, user_name, oauth_provider, oauth_id) VALUES (%s,%s,%s,%s) RETURNING user_id",
                    (session['pending_oauth_registration']['email'], 
                     session['pending_oauth_registration']['name'], 
                     session['pending_oauth_registration']['oauth_provider'],
                     session['pending_oauth_registration']['oauth_id'])
                )
                new_user = cur.fetchone()
                conn.commit()
                
                # Set session for new user
                session["user_id"] = new_user["user_id"]
                session["is_admin"] = False
                
                # Clear pending OAuth registration
                session.pop('pending_oauth_registration', None)
                
                flash(f"Account created and logged in via {session['pending_oauth_registration']['oauth_provider'].title()}!")
                return redirect(url_for("dashboard"))
            except Exception as e:
                conn.rollback()
                flash(f"Error creating account: {str(e)}")
                return redirect(url_for("login"))
            finally:
                cur.close(); conn.close()
        else:
            flash("Invalid or expired OTP. Please try again.")
            return redirect(url_for("verify_oauth_otp"))
    
    return render_template("verify_otp.html")

# Login (manual)
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_connection()
        cur = dict_cursor(conn)
        cur.execute("SELECT user_id, password FROM users WHERE user_email=%s", (email,))
        row = cur.fetchone()

        if not row or not row.get("password") or not check_password_hash(row["password"], password):
            cur.close(); conn.close()
            flash("Invalid credentials.")
            return redirect(url_for("login"))

        session["user_id"] = row["user_id"]
        
        # Check if user is admin and set session flag
        cur.execute("SELECT is_admin FROM users WHERE user_id=%s", (row["user_id"],))
        admin_row = cur.fetchone()
        session["is_admin"] = admin_row and admin_row.get("is_admin", False)
        
        cur.close(); conn.close()
        
        flash("Logged in.")
        return redirect(url_for("preview_dashboard"))
    return render_template("login.html")

# Quick login via QR token
@app.route("/quick_login/<token>")
def quick_login(token):
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_id FROM users WHERE quick_login_token=%s", (token,))
    row = cur.fetchone()
    if not row:
        cur.close(); conn.close()
        flash("Invalid or expired QR login.")
        return redirect(url_for("login"))
    
    session["user_id"] = row["user_id"]
    
    # Check if user is admin and set session flag
    cur.execute("SELECT is_admin FROM users WHERE user_id=%s", (row["user_id"],))
    admin_row = cur.fetchone()
    session["is_admin"] = admin_row and admin_row.get("is_admin", False)
    
    cur.close(); conn.close()
    
    flash("Logged in via QR.")
    return redirect(url_for("dashboard"))

# OAuth Routes
@app.route("/auth/<provider>")
def oauth_login(provider):
    try:
        if provider == 'google':
            if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
                flash("Google OAuth is not configured. Please contact administrator.")
                return redirect(url_for("login"))
            # Use the correct redirect URI that matches Google Cloud Console configuration
            redirect_uri = "http://127.0.0.1:5001/auth/google/callback"
            return google.authorize_redirect(redirect_uri)
        elif provider == 'microsoft':
            if not MICROSOFT_CLIENT_ID or not MICROSOFT_CLIENT_SECRET:
                flash("Microsoft OAuth is not configured. Please contact administrator.")
                return redirect(url_for("login"))
            redirect_uri = url_for('oauth_callback', provider='microsoft', _external=True)
            return microsoft.authorize_redirect(redirect_uri)
        else:
            flash("Invalid OAuth provider.")
            return redirect(url_for("login"))
    except Exception as e:
        flash(f"OAuth initialization failed: {str(e)}")
        return redirect(url_for("login"))

# Google OAuth callback route (matches Google Cloud Console configuration)
@app.route("/auth/google/callback")
def google_callback():
    return oauth_callback('google')

# Main callback route for our application
@app.route("/auth/<provider>/callback")
def oauth_callback(provider):
    try:
        if provider == 'google':
            token = google.authorize_access_token()  # Access token from google (needed to get user info)
            resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scope
            user_info = resp.json()
            
            if 'email' in user_info:
                email = user_info['email']
                name = user_info.get('name', '')
                oauth_id = user_info.get('id')
            else:
                flash("Failed to get user information from Google.")
                return redirect(url_for("login"))
        elif provider == 'microsoft':
            token = microsoft.authorize_access_token()
            resp = microsoft.get('userinfo')  # Get user info from Microsoft
            user_info = resp.json()
            email = user_info.get('mail') or user_info.get('userPrincipalName')
            name = user_info.get('displayName', '')
            oauth_id = user_info.get('id')
        else:
            flash("Invalid OAuth provider.")
            return redirect(url_for("login"))

        # Validate email domain
        if not email or not email.endswith("@mhssce.ac.in"):
            flash("Please use your @mhssce.ac.in email address.")
            return redirect(url_for("login"))

        # Check if user exists
        conn = get_connection()
        cur = dict_cursor(conn)
        cur.execute("SELECT user_id FROM users WHERE user_email=%s", (email.lower(),))
        existing_user = cur.fetchone()
        
        if existing_user:
            # Update OAuth info for existing user
            cur.execute(
                "UPDATE users SET oauth_provider=%s, oauth_id=%s WHERE user_id=%s",
                (provider, oauth_id, existing_user["user_id"])
            )
            conn.commit()
            session["user_id"] = existing_user["user_id"]
            
            # Check if user is admin and set session flag
            cur.execute("SELECT is_admin FROM users WHERE user_id=%s", (existing_user["user_id"],))
            admin_row = cur.fetchone()
            session["is_admin"] = admin_row and admin_row.get("is_admin", False)
            
            flash(f"Logged in successfully via {provider.title()}!")
        else:
            # Generate OTP for new user verification
            otp = generate_otp()
            store_otp(email, otp)
            
            if email_service.send_otp_email(email, otp):
                # Store OAuth data in session temporarily
                session['pending_oauth_registration'] = {
                    'email': email.lower(),
                    'name': name,
                    'oauth_provider': provider,
                    'oauth_id': oauth_id
                }
                flash("OTP sent to your email. Please verify to complete registration.")
                return redirect(url_for('verify_oauth_otp'))
            else:
                flash("Failed to send OTP. Please try again.")
                return redirect(url_for("login"))
        
        cur.close(); conn.close()
        return redirect(url_for("dashboard"))
        
    except Exception as e:
        flash(f"OAuth authentication failed: {str(e)}")
        return redirect(url_for("login"))

# Logout
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Logged out.")
    return redirect(url_for("index"))

# Dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_name, user_email, credits, profile_picture FROM users WHERE user_id=%s", (uid,))
    user = cur.fetchone()

    cur.execute("SELECT doc_id, doc_name, upload_date, doc_type FROM documents WHERE user_id=%s ORDER BY upload_date DESC", (uid,))
    docs = cur.fetchall()
    
    # Get transaction history for the user
    cur.execute("""SELECT trans_id, amount, status, description, created_at 
                    FROM transaction_historys 
                    WHERE user_id=%s 
                    ORDER BY created_at DESC 
                    LIMIT 10""", (uid,))
    transactions = cur.fetchall()
    
    cur.close(); conn.close()

    return render_template("dashboard.html", user=user, docs=docs, transactions=transactions)

# Preview Dashboard (view-only)
@app.route("/preview_dashboard")
@login_required
def preview_dashboard():
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_name, user_email, credits, profile_picture FROM users WHERE user_id=%s", (uid,))
    user = cur.fetchone()

    cur.execute("SELECT doc_id, doc_name, upload_date FROM documents WHERE user_id=%s ORDER BY upload_date DESC", (uid,))
    docs = cur.fetchall()
    
    cur.close(); conn.close()

    return render_template("preview_dashboard.html", user=user, docs=docs)

# Preview Document (view-only)
@app.route("/preview_document/<int:doc_id>")
@login_required
def preview_document(doc_id):
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    
    # Get document info
    cur.execute("""
        SELECT doc_id, doc_name, upload_date, doc_type 
        FROM documents 
        WHERE doc_id=%s AND user_id=%s
    """, (doc_id, uid))
    doc = cur.fetchone()
    
    if not doc:
        flash("Document not found.", "error")
        return redirect(url_for("preview_dashboard"))
    
    cur.close(); conn.close()
    
    return render_template("preview_document.html", 
                        doc_id=doc["doc_id"],
                        doc_name=doc["doc_name"], 
                        upload_date=doc["upload_date"].strftime("%Y-%m-%d %H:%M"),
                        doc_type=doc.get("doc_type", "application/octet-stream"))

# Previously printed files (temp_documents)
@app.route("/previously_printed")
@login_required
def previously_printed():
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    
    # Get previously printed documents from temp_documents
    cur.execute("""SELECT temp_doc_id, original_name, created_at, expires_at 
                    FROM temp_documents 
                    WHERE user_id=%s 
                    ORDER BY created_at DESC""", (uid,))
    temp_docs = cur.fetchall()
    
    cur.close(); conn.close()
    
    return render_template("previously_printed.html", temp_docs=temp_docs)

# Restore document from temp_documents to documents
@app.route("/restore_document/<int:temp_doc_id>", methods=["POST"])
@login_required
def restore_document(temp_doc_id):
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    
    try:
        # Get the temp document data
        cur.execute("""SELECT original_name, doc_blob, doc_type 
                        FROM temp_documents 
                        WHERE temp_doc_id=%s AND user_id=%s""", 
                    (temp_doc_id, uid))
        temp_doc = cur.fetchone()
        
        if not temp_doc:
            flash("Document not found or access denied.")
            return redirect(url_for("previously_printed"))
        
        # Insert back into documents table
        cur.execute("""INSERT INTO documents (user_id, doc_blob, doc_type, doc_name, upload_date) 
                        VALUES (%s, %s, %s, %s, %s) RETURNING doc_id""",
                    (uid, temp_doc["doc_blob"], temp_doc["doc_type"], 
                     temp_doc["original_name"], datetime.datetime.utcnow()))
        
        new_doc_id = cur.fetchone()["doc_id"]
        
        # Delete from temp_documents
        cur.execute("DELETE FROM temp_documents WHERE temp_doc_id=%s", (temp_doc_id,))
        
        conn.commit()
        flash(f"Document '{temp_doc['original_name']}' restored successfully!")
        return redirect(url_for("dashboard"))
        
    except Exception as e:
        conn.rollback()
        flash(f"Error restoring document: {str(e)}")
        return redirect(url_for("previously_printed"))
    finally:
        cur.close(); conn.close()

# Settings page
@app.route("/settings")
@login_required
def settings():
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_name, user_email, credits, created_at, is_admin, profile_picture FROM users WHERE user_id=%s", (uid,))
    user = cur.fetchone()
    cur.close(); conn.close()
    return render_template("settings.html", user=user)

# Change username with OTP verification
@app.route("/change_username", methods=["POST"])
@login_required
def change_username():
    new_username = request.form.get("new_username", "").strip()
    
    # Validate username
    if not new_username or len(new_username) < 3 or len(new_username) > 20:
        flash("Username must be between 3-20 characters.")
        return redirect(url_for("settings"))
    
    # Check if username contains only allowed characters
    if not re.match(r'^[a-zA-Z0-9_]+$', new_username):
        flash("Username can only contain letters, numbers, and underscores.")
        return redirect(url_for("settings"))
    
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    
    # Check if username is already taken
    cur.execute("SELECT user_id FROM users WHERE user_name=%s AND user_id!=%s", (new_username, uid))
    if cur.fetchone():
        cur.close(); conn.close()
        flash("Username is already taken.")
        return redirect(url_for("settings"))
    
    # Generate OTP
    otp = str(random.randint(100000, 999999))
    otp_expires = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    
    # Store OTP in session
    session["username_change_otp"] = otp
    session["username_change_otp_expires"] = otp_expires.isoformat()
    session["new_username"] = new_username
    
    # Get user's email
    cur.execute("SELECT user_email FROM users WHERE user_id=%s", (uid,))
    user_email = cur.fetchone()["user_email"]
    
    # Send OTP email using Postmark
    try:
        success = email_service.send_username_change_email(user_email, new_username, otp)
        
        cur.close()
        conn.close()
        if success:
            flash("Verification code sent to your email. Please enter the code to confirm the username change.")
            return redirect(url_for("verify_username_change"))
        else:
            flash("Error sending verification email. Please try again.")
            return redirect(url_for("settings"))
    except Exception as e:
        cur.close()
        conn.close()
        flash(f"Error sending verification email: {str(e)}")
        return redirect(url_for("settings"))

# Verify username change with OTP
@app.route("/verify_username_change", methods=["GET", "POST"])
@login_required
def verify_username_change():
    if request.method == "GET":
        return render_template("verify_username_change.html")
    
    entered_otp = request.form.get("otp", "").strip()
    
    # Check if OTP exists in session
    if "username_change_otp" not in session:
        flash("No verification code found. Please request a new one.")
        return redirect(url_for("settings"))
    
    # Check OTP expiry
    otp_expires = datetime.datetime.fromisoformat(session["username_change_otp_expires"])
    if datetime.datetime.utcnow() > otp_expires:
        session.pop("username_change_otp", None)
        session.pop("username_change_otp_expires", None)
        session.pop("new_username", None)
        flash("Verification code expired. Please request a new one.")
        return redirect(url_for("settings"))
    
    # Verify OTP
    if entered_otp != session["username_change_otp"]:
        flash("Invalid verification code. Please try again.")
        return redirect(url_for("verify_username_change"))
    
    # OTP is correct, update username
    uid = session["user_id"]
    new_username = session["new_username"]
    
    conn = get_connection()
    cur = dict_cursor(conn)
    try:
        cur.execute("UPDATE users SET user_name=%s WHERE user_id=%s", (new_username, uid))
        conn.commit()
        
        # Clear session data
        session.pop("username_change_otp", None)
        session.pop("username_change_otp_expires", None)
        session.pop("new_username", None)
        
        flash(f"Username successfully changed to {new_username}!")
        return redirect(url_for("settings"))
        
    except Exception as e:
        conn.rollback()
        flash(f"Error updating username: {str(e)}")
        return redirect(url_for("settings"))
    finally:
        cur.close(); conn.close()

# Upload profile picture
@app.route("/upload_profile_picture", methods=["POST"])
@login_required
def upload_profile_picture():
    if "profile_picture" not in request.files:
        flash("No file selected.")
        return redirect(url_for("settings"))
    
    file = request.files["profile_picture"]
    if file.filename == "":
        flash("No file selected.")
        return redirect(url_for("settings"))
    
    # Validate file type
    allowed_extensions = {"png", "jpg", "jpeg", "gif"}
    file_ext = file.filename.rsplit(".", 1)[1].lower() if "." in file.filename else ""
    
    if file_ext not in allowed_extensions:
        flash("Only image files (PNG, JPG, JPEG, GIF) are allowed.")
        return redirect(url_for("settings"))
    
    # Read file data
    try:
        image_data = file.read()
        
        # Optional: Resize image to reasonable size (max 500KB)
        if len(image_data) > 500 * 1024:  # 500KB
            flash("Image size should not exceed 500KB.")
            return redirect(url_for("settings"))
        
        uid = session["user_id"]
        conn = get_connection()
        cur = dict_cursor(conn)
        
        cur.execute("UPDATE users SET profile_picture=%s WHERE user_id=%s", 
                   (psycopg2.Binary(image_data), uid))
        conn.commit()
        
        flash("Profile picture updated successfully!")
        return redirect(url_for("settings"))
        
    except Exception as e:
        conn.rollback()
        flash(f"Error uploading profile picture: {str(e)}")
        return redirect(url_for("settings"))
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# Change password (for logged-in users)
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    """Allow logged-in users to change their password"""
    if request.method == "POST":
        current_password = request.form.get("current_password", "").strip()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        
        # Validate inputs
        if not current_password or not new_password or not confirm_password:
            flash("Please fill in all fields.")
            return redirect(url_for("change_password"))
        
        if new_password != confirm_password:
            flash("New passwords do not match.")
            return redirect(url_for("change_password"))
        
        if len(new_password) < 6:
            flash("Password must be at least 6 characters long.")
            return redirect(url_for("change_password"))
        
        # Verify current password
        uid = session["user_id"]
        conn = get_connection()
        cur = dict_cursor(conn)
        
        try:
            cur.execute("SELECT password FROM users WHERE user_id = %s", (uid,))
            result = cur.fetchone()
            
            if not result or not check_password_hash(result["password"], current_password):
                flash("Current password is incorrect.")
                return redirect(url_for("change_password"))
            
            # Update password
            hashed_password = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password = %s WHERE user_id = %s", 
                       (hashed_password, uid))
            conn.commit()
            
            flash("Password changed successfully!")
            return redirect(url_for("settings"))
            
        except Exception as e:
            conn.rollback()
            flash(f"Error changing password: {str(e)}")
            return redirect(url_for("change_password"))
        finally:
            cur.close()
            conn.close()
    
    return render_template("change_password.html")

# Upload document (stores doc_blob in DB)
@app.route("/upload", methods=["GET","POST"])
@login_required
def upload():
    if request.method == "POST":
        if "pdf_file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        file = request.files["pdf_file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)
        if not allowed_file(file.filename):
            flash("Only PDF, DOCX, DOC, and image files (JPG, PNG, GIF, BMP, TIFF, WebP) are allowed.")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        mime = file.mimetype or "application/pdf"
        data = file.read()  # bytes

        uid = session["user_id"]
        conn = get_connection()
        cur = dict_cursor(conn)
        try:
            # Check if file conversion is needed
            file_ext = os.path.splitext(filename)[1].lower()
            if is_conversion_required(filename):
                # Convert file to PDF before storing
                temp_file = None
                converted_pdf_path = None
                try:
                    # Create temporary file
                    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file_obj:
                        temp_file = temp_file_obj.name
                        temp_file_obj.write(data)
                    
                    # Convert to PDF
                    converted_pdf_path = get_converted_pdf_path(temp_file)
                    convert_to_pdf(temp_file, converted_pdf_path)
                    
                    # Read converted PDF
                    with open(converted_pdf_path, 'rb') as pdf_file:
                        data = pdf_file.read()
                    
                    # Update filename and mime type
                    filename = os.path.splitext(filename)[0] + ".pdf"
                    mime = "application/pdf"
                    
                finally:
                    # Clean up temporary files safely
                    if temp_file and os.path.exists(temp_file):
                        try:
                            os.unlink(temp_file)
                        except:
                            pass  # Ignore cleanup errors
                    if converted_pdf_path and os.path.exists(converted_pdf_path):
                        try:
                            os.unlink(converted_pdf_path)
                        except:
                            pass  # Ignore cleanup errors

            cur.execute(
                "INSERT INTO documents (user_id, doc_blob, doc_type, doc_name) VALUES (%s,%s,%s,%s) RETURNING doc_id",
                (uid, psycopg2.Binary(data), mime, filename)
            )
            doc_id = cur.fetchone()["doc_id"]

            # If first upload, generate quick-login token + QR and store
            cur.execute("SELECT quick_login_token FROM users WHERE user_id=%s", (uid,))
            row = cur.fetchone()
            if not row or not row.get("quick_login_token"):
                token = secrets.token_urlsafe(16)
                # Use hardcoded IP address and correct port for local development
                import socket
                ip_address = socket.gethostbyname(socket.gethostname())
                qr_payload = f"http://{ip_address}:5001/quick_login/{token}"
                qr = qrcode.make(qr_payload)
                buf = io.BytesIO()
                qr.save(buf, format="PNG")
                qr_bytes = buf.getvalue()

                cur.execute(
                    "UPDATE users SET quick_login_token=%s, qr_code=%s WHERE user_id=%s",
                    (token, psycopg2.Binary(qr_bytes), uid)
                )

            conn.commit()
            flash("File uploaded and saved to your account.")
            return redirect(url_for("dashboard"))
        except Exception as e:
            conn.rollback()
            flash("Upload error: " + str(e))
            return redirect(request.url)
        finally:
            cur.close(); conn.close()

    return render_template("upload.html")

# Download document
@app.route("/document/<int:doc_id>/download")
@login_required
def download_document(doc_id):
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_id, doc_blob, doc_type, doc_name FROM documents WHERE doc_id=%s", (doc_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        flash("Document not found.")
        return redirect(url_for("dashboard"))
    if row["user_id"] != uid:
        flash("Access denied.")
        return redirect(url_for("dashboard"))

    data = row["doc_blob"]
    name = row["doc_name"]
    mime = row["doc_type"] or "application/pdf"

    # Convert memoryview to bytes if needed
    if isinstance(data, memoryview):
        data = data.tobytes()

    # make response
    resp = make_response(data)
    resp.headers.set("Content-Type", mime)
    resp.headers.set("Content-Disposition", f"attachment; filename={name}")
    return resp

# Rename document
@app.route("/document/<int:doc_id>/rename", methods=["POST"])
@login_required
def rename_document(doc_id):
    new_name = request.form.get("new_name", "").strip()
    if not new_name:
        flash("New name required.")
        return redirect(url_for("dashboard"))
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_id FROM documents WHERE doc_id=%s", (doc_id,))
    row = cur.fetchone()
    if not row or row["user_id"] != uid:
        cur.close(); conn.close()
        flash("Access denied.")
        return redirect(url_for("dashboard"))
    try:
        cur.execute("UPDATE documents SET doc_name=%s WHERE doc_id=%s", (new_name, doc_id))
        conn.commit()
        flash("Renamed.")
    except Exception as e:
        conn.rollback()
        flash("Error renaming: " + str(e))
    finally:
        cur.close(); conn.close()
    return redirect(url_for("dashboard"))

# Delete document
@app.route("/document/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_id FROM documents WHERE doc_id=%s", (doc_id,))
    row = cur.fetchone()
    if not row or row["user_id"] != uid:
        cur.close(); conn.close()
        flash("Access denied.")
        return redirect(url_for("dashboard"))
    try:
        cur.execute("DELETE FROM documents WHERE doc_id=%s", (doc_id,))
        conn.commit()
        flash("Deleted.")
    except Exception as e:
        conn.rollback()
        flash("Delete error: " + str(e))
    finally:
        cur.close(); conn.close()
    return redirect(url_for("dashboard"))

# ----- Razorpay: create order for credits -----
@app.route("/buy_credits", methods=["GET","POST"])
@login_required
def buy_credits():
    # Check if Razorpay is configured
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        flash("Payment system is not configured. Please contact administrator.")
        return redirect(url_for("dashboard"))
        
    if request.method == "POST":
        amount_rupees = float(request.form.get("amount", "0"))
        if amount_rupees <= 0:
            flash("Enter valid amount.")
            return redirect(url_for("buy_credits"))
        amount_paise = int(amount_rupees * 100)

        try:
            client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
            order = client.order.create(dict(amount=amount_paise, currency="INR", receipt=f"rcpt_{secrets.token_hex(8)}", notes={"user_id": session["user_id"]}))
            order_id = order.get("id")
        except Exception as e:
            flash(f"Payment system error: {str(e)}")
            return redirect(url_for("buy_credits"))

        # Record transaction in DB (status = created)
        conn = get_connection()
        cur = dict_cursor(conn)
        try:
            cur.execute(
                """INSERT INTO transaction_historys (user_id, amount, razorpay_order_id, status, description)
                VALUES (%s,%s,%s,%s,%s) RETURNING trans_id""",
                (session["user_id"], amount_rupees, order_id, "created", f"Credit purchase: ₹{amount_rupees} = {amount_rupees} credits")
            )
            conn.commit()
            trans_id = cur.fetchone()["trans_id"]
        except Exception as e:
            conn.rollback()
            flash("Error creating transaction: " + str(e))
            return redirect(url_for("buy_credits"))
        finally:
            cur.close(); conn.close()

        # Store transaction info in session for payment_success route
        session['current_transaction'] = {
            'order_id': order_id,
            'amount': amount_rupees,
            'credits': amount_rupees,  # 1:1 ratio
            'trans_id': trans_id
        }

        # Return order info (frontend will use razorpay checkout)
        return render_template("pay.html", order=order, key_id=RAZORPAY_KEY_ID, amount=amount_rupees, trans_id=trans_id)

    return render_template("buy_credits.html")

# Razorpay webhook - verify signature & update DB
@app.route("/razorpay/webhook", methods=["POST"])
def razorpay_webhook():
    # Check if Razorpay is configured
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET or not RAZORPAY_WEBHOOK_SECRET:
        return "", 400
        
    payload = request.get_data()
    signature = request.headers.get("X-Razorpay-Signature", "")
    client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    try:
        # verify signature
        client.utility.verify_webhook_signature(payload, signature, RAZORPAY_WEBHOOK_SECRET)
    except Exception as e:
        return "", 400

    event = request.json
    print(f"Webhook received: {event}")
    # Keep it simple: only handle payment.captured
    if event and event.get("event") == "payment.captured":
        payload_data = event.get("payload", {})
        payment = payload_data.get("payment", {}).get("entity", {})
        order_id = payment.get("order_id")
        amount = payment.get("amount")  # paise
        amount_rupees = float(amount) / 100.0 if amount else 0.0
        razorpay_payment_id = payment.get("id")

        conn = get_connection()
        cur = dict_cursor(conn)
        try:
            # update transaction entry
            cur.execute(
                """UPDATE transaction_historys SET razorpay_payment_id=%s, status=%s WHERE razorpay_order_id=%s RETURNING user_id, amount""",
                (razorpay_payment_id, "paid", order_id)
            )
            row = cur.fetchone()
            if row:
                user_id = row["user_id"]
                # Use the amount from the transaction record (user's selected amount), not the payment amount
                selected_amount = row["amount"]
                print(f"Webhook found transaction - User: {user_id}, Selected amount: {selected_amount}")
                # add credits to user (1 rupee = 1 credit)
                cur.execute("UPDATE users SET credits = credits + %s WHERE user_id=%s", (selected_amount, user_id))
                conn.commit()
                print(f"Webhook successfully added {selected_amount} credits to user {user_id}")
            else:
                print(f"Webhook: No transaction found for order_id: {order_id}")
        except Exception as e:
            conn.rollback()
            print(f"Error in webhook: {str(e)}")
            # Log the error for debugging
            import traceback
            traceback.print_exc()
        finally:
            cur.close(); conn.close()

    return "", 200

# ---- Admin views ----
@app.route("/admin/users")
@admin_required
def admin_users():
    """Admin users management page"""
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        cur.execute("SELECT user_id, user_email, user_name, credits, created_at FROM users ORDER BY created_at DESC")
        users = cur.fetchall()
        cur.close(); conn.close()
        return render_template("admin_users.html", users=users)
    except Exception as e:
        flash(f"Error loading users: {str(e)}")
        return redirect(url_for('admin_dashboard'))

@app.route("/admin/transactions")
@admin_required
def admin_transactions():
    """Admin transactions view page"""
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        cur.execute("""
            SELECT th.*, u.user_name, u.user_email 
            FROM transaction_historys th 
            JOIN users u ON th.user_id = u.user_id 
            ORDER BY th.created_at DESC
        """)
        transactions = cur.fetchall()
        cur.close(); conn.close()
        return render_template("admin_transactions.html", transactions=transactions)
    except Exception as e:
        flash(f"Error loading transactions: {str(e)}")
        return redirect(url_for('admin_dashboard'))

@app.route("/admin/print_jobs")
@admin_required
def admin_print_jobs():
    """Admin print jobs view page"""
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        cur.execute("""
            SELECT pj.*, u.user_name, u.user_email, d.doc_name 
            FROM print_jobs pj 
            JOIN users u ON pj.user_id = u.user_id 
            JOIN documents d ON pj.doc_id = d.doc_id 
            ORDER BY pj.requested_at DESC
        """)
        jobs = cur.fetchall()
        cur.close(); conn.close()
        return render_template("admin_print_jobs.html", jobs=jobs)
    except Exception as e:
        flash(f"Error loading print jobs: {str(e)}")
        return redirect(url_for('admin_dashboard'))

# User Transaction History
@app.route("/transactions")
@login_required
def transactions():
    """Display user's transaction history"""
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    
    try:
        # Get user info
        cur.execute("SELECT user_name, user_email, credits FROM users WHERE user_id=%s", (uid,))
        user = cur.fetchone()
        
        # Get all transactions for this user
        cur.execute("""
            SELECT trans_id, amount, status, description, created_at 
            FROM transaction_historys 
            WHERE user_id=%s 
            ORDER BY created_at DESC
        """, (uid,))
        transactions = cur.fetchall()
        
        # Calculate summary statistics
        cur.execute("""
            SELECT 
                SUM(CASE WHEN status = 'paid' AND amount > 0 THEN amount ELSE 0 END) as total_spent,
                SUM(CASE WHEN status = 'paid' AND amount > 0 THEN amount ELSE 0 END) as total_credits_purchased,
                COUNT(*) as total_transactions,
                COUNT(CASE WHEN status = 'paid' THEN 1 END) as successful_transactions
            FROM transaction_historys 
            WHERE user_id=%s
        """, (uid,))
        summary = cur.fetchone()
        
        cur.close(); conn.close()
        
        return render_template("transactions.html", 
                             user=user, 
                             transactions=transactions,
                             total_spent=summary['total_spent'] or 0,
                             total_credits_purchased=summary['total_credits_purchased'] or 0,
                             total_transactions=summary['total_transactions'] or 0,
                             successful_transactions=summary['successful_transactions'] or 0)
    except Exception as e:
        cur.close(); conn.close()
        flash(f"Error loading transactions: {str(e)}")
        return redirect(url_for('dashboard'))

# User Print History
@app.route("/print_history")
@login_required
def print_history():
    """Display user's print job history"""
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    
    try:
        # Get user info
        cur.execute("SELECT user_name, user_email, credits FROM users WHERE user_id=%s", (uid,))
        user = cur.fetchone()
        
        # Get all print jobs for this user with document names
        # Use stored document_name to preserve document names permanently
        cur.execute("""
            SELECT pj.job_id, pj.doc_id, pj.document_name as doc_name, 
                   pj.printer, pj.page_range, pj.copies, pj.duplex, pj.credits_deducted, 
                   pj.status, pj.requested_at, pj.printed_at
            FROM print_jobs pj
            WHERE pj.user_id=%s 
            ORDER BY pj.requested_at DESC
        """, (uid,))
        print_jobs = cur.fetchall()
        
        # Calculate summary statistics
        cur.execute("""
            SELECT 
                COUNT(*) as total_jobs,
                COUNT(CASE WHEN status = 'printed' THEN 1 END) as successful_jobs,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_jobs,
                SUM(credits_deducted) as total_credits_used
            FROM print_jobs 
            WHERE user_id=%s
        """, (uid,))
        summary = cur.fetchone()
        
        cur.close(); conn.close()
        
        return render_template("print_history.html", 
                             user=user, 
                             print_jobs=print_jobs,
                             total_jobs=summary['total_jobs'] or 0,
                             successful_jobs=summary['successful_jobs'] or 0,
                             pending_jobs=summary['pending_jobs'] or 0,
                             total_credits_used=summary['total_credits_used'] or 0)
    except Exception as e:
        cur.close(); conn.close()
        flash(f"Error loading print history: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route("/print/<int:doc_id>", methods=["POST"])
@login_required
def print_document(doc_id):
    uid = session["user_id"]
    printer_name = request.form.get("printer")
    page_range = request.form.get("page_range", "").strip()
    watermark = request.form.get("watermark", "").strip()
    copies = int(request.form.get("copies", "1"))
    duplex = bool(request.form.get("duplex"))

    # Fetch document from DB and get user credits
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_id, doc_blob, doc_type, doc_name FROM documents WHERE doc_id=%s", (doc_id,))
    row = cur.fetchone()
    if not row or row["user_id"] != uid:
        cur.close(); conn.close()
        flash("❌ Access denied or document not found.")
        return redirect(url_for("dashboard"))

    # Get user credits
    cur.execute("SELECT credits FROM users WHERE user_id=%s", (uid,))
    user_credits = cur.fetchone()["credits"]

    # Calculate pages to print and credits required
    temp_dir = tempfile.gettempdir()
    # Sanitize the filename for filesystem use
    safe_filename = secure_filename(row["doc_name"])
    input_pdf = os.path.join(temp_dir, safe_filename)
    doc_data = row["doc_blob"]
    
    # Convert memoryview to bytes if needed
    if isinstance(doc_data, memoryview):
        doc_data = doc_data.tobytes()
    
    with open(input_pdf, "wb") as f:
        f.write(doc_data)

    # Get total pages in PDF
    import fitz  # PyMuPDF
    pdf_doc = fitz.open(input_pdf)
    total_pages = pdf_doc.page_count
    pdf_doc.close()

    # Calculate pages to print
    def parse_page_range(page_range, total_pages):
        if not page_range or page_range.strip() == '':
            return total_pages
        
        pages = set()
        ranges = page_range.split(',')
        
        for range_str in ranges:
            range_str = range_str.strip()
            if '-' in range_str:
                try:
                    start, end = range_str.split('-')
                    start = int(start.strip())
                    end = int(end.strip())
                    if start > 0 and end <= total_pages and start <= end:
                        for i in range(start, end + 1):
                            pages.add(i)
                except:
                    pass
            else:
                try:
                    page = int(range_str.strip())
                    if page > 0 and page <= total_pages:
                        pages.add(page)
                except:
                    pass
        
        return len(pages) or total_pages
    
    pages_to_print = parse_page_range(page_range, total_pages) * copies

    # Apply duplex discount
    if duplex:
        pages_to_print = (pages_to_print + 1) // 2  # Round up for duplex

    credits_required = pages_to_print * 2  # 2 credits per page

    # Check if user has enough credits
    if user_credits < credits_required:
        cur.close(); conn.close()
        flash(f"❌ Insufficient credits. You have {user_credits} credits, but {credits_required} credits are required.")
        return redirect(url_for("print_page", doc_id=doc_id))

    # Get the original filename without extension and add suffixes
    base_filename = os.path.splitext(row["doc_name"])[0]
    watermarked_pdf = os.path.join(temp_dir, f"{base_filename}_watermarked.pdf")
    final_pdf = os.path.join(temp_dir, f"{base_filename}_final.pdf")

    # Insert into print_jobs (pending)
    cur.execute(
        """INSERT INTO print_jobs (user_id, doc_id, document_name, printer, page_range, watermark, copies, status, duplex, credits_deducted)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING job_id""",
        (uid, doc_id, row["doc_name"], printer_name, page_range, watermark, copies, "pending", duplex, credits_required)
    )
    job_id = cur.fetchone()["job_id"]
    conn.commit()

    try:
        # Step 1: Watermark
        add_watermark(input_pdf, watermarked_pdf, watermark)
        # Step 2: Extract pages
        extract_pages(watermarked_pdf, final_pdf, page_range)
        # Step 3: Print
        print_pdf(final_pdf, printer_name, copies=copies, duplex=duplex)

        # Delete the document from main documents table after successful printing
        cur.execute("DELETE FROM documents WHERE doc_id=%s", (doc_id,))
        
        # Move document to temporary storage for 7-day retention
        cur.execute("""
            INSERT INTO temp_documents (user_id, doc_blob, doc_type, original_name, created_at, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (uid, row["doc_blob"], row["doc_type"], row["doc_name"], 
              datetime.datetime.utcnow(), datetime.datetime.utcnow() + datetime.timedelta(days=7)))
        
        # Deduct credits and update job status
        cur.execute(
            "UPDATE users SET credits = credits - %s WHERE user_id=%s",
            (credits_required, uid)
        )
        cur.execute(
            "UPDATE print_jobs SET status=%s, printed_at=%s, credits_deducted=%s WHERE job_id=%s",
            ("printed", datetime.datetime.utcnow(), credits_required, job_id)
        )
        conn.commit()
        flash(f"✅ Document sent to printer. {credits_required} credits deducted from your account.")
        
        # Record credit deduction in transaction history
        cur.execute(
            """INSERT INTO transaction_historys (user_id, amount, status, description, created_at)
               VALUES (%s,%s,%s,%s,%s)""",
            (uid, -credits_required, "completed", f"Print job #{job_id} - {pages_to_print} pages", datetime.datetime.utcnow())
        )
        conn.commit()
        
    except Exception as e:
        conn.rollback()
        # Refund credits for failed print job
        cur.execute(
            "UPDATE users SET credits = credits + %s WHERE user_id=%s",
            (credits_required, uid)
        )
        cur.execute("UPDATE print_jobs SET status=%s WHERE job_id=%s", ("failed", job_id))
        conn.commit()
        
        # Record credit refund in transaction history
        cur.execute(
            """INSERT INTO transaction_historys (user_id, amount, status, description, created_at)
               VALUES (%s,%s,%s,%s,%s)""",
            (uid, credits_required, "completed", f"Refund for failed print job #{job_id}", datetime.datetime.utcnow())
        )
        conn.commit()
        flash(f"❌ Print failed: {e}. {credits_required} credits have been refunded to your account.")
    finally:
        cur.close(); conn.close()

    return redirect(url_for("dashboard"))
@app.route("/print_page/<int:doc_id>")
@login_required
def print_page(doc_id):
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_id, doc_name FROM documents WHERE doc_id=%s", (doc_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    
    if not row or row["user_id"] != uid:
        flash("Access denied or document not found.")
        return redirect(url_for("dashboard"))
    
    # For Railway deployment, return mock printers since actual printing is not available
    printers = ["Mock Printer 1", "Mock Printer 2", "Mock Printer 3"]
    return render_template("print.html", doc_id=doc_id, doc_name=row["doc_name"], printers=printers)

@app.route("/view_pdf/<int:doc_id>")
@login_required
def view_pdf(doc_id):
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT user_id, doc_blob, doc_type, doc_name FROM documents WHERE doc_id=%s", (doc_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    
    if not row or row["user_id"] != uid:
        flash("Access denied or document not found.")
        return redirect(url_for("dashboard"))
    
    data = row["doc_blob"]
    mime = row["doc_type"] or "application/pdf"
    
    # Convert memoryview to bytes if needed
    if isinstance(data, memoryview):
        data = data.tobytes()
    
    # Create response to display PDF inline
    resp = make_response(data)
    resp.headers.set("Content-Type", mime)
    resp.headers.set("Content-Disposition", "inline")
    return resp

@app.route("/debug/oauth")
@login_required
def debug_oauth():
    """Debug route to check OAuth configuration"""
    # Only allow admin users to access debug routes
    if not session.get('is_admin', False):
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('dashboard'))
        
    return f"""
    <h2>OAuth Debug Information</h2>
    <p><strong>Google Client ID:</strong> {GOOGLE_CLIENT_ID[:20] + '...' if GOOGLE_CLIENT_ID else 'Not set'}</p>
    <p><strong>Google Client Secret:</strong> {'Set' if GOOGLE_CLIENT_SECRET else 'Not set'}</p>
    <p><strong>Microsoft Client ID:</strong> {MICROSOFT_CLIENT_ID[:20] + '...' if MICROSOFT_CLIENT_ID else 'Not set'}</p>
    <p><strong>Microsoft Client Secret:</strong> {'Set' if MICROSOFT_CLIENT_SECRET else 'Not set'}</p>
    <p><strong>Google OAuth Configured:</strong> {'Yes' if google else 'No'}</p>
    <p><strong>Microsoft OAuth Configured:</strong> {'Yes' if microsoft else 'No'}</p>
    <hr>
    <a href="/auth/google">Test Google OAuth</a><br>
    <a href="/debug/razorpay">Test Razorpay</a><br>
    <a href="/">Back to Home</a>
    """

@app.route("/debug/razorpay")
@login_required
def debug_razorpay():
    """Debug route to check Razorpay configuration"""
    # Only allow admin users to access debug routes
    if not session.get('is_admin', False):
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('dashboard'))
        
    razorpay_status = "Not configured"
    test_result = "Not tested"
    
    if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
        razorpay_status = "Configured"
        try:
            import razorpay
            client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
            # Test with a small order creation
            test_order = client.order.create({
                'amount': 100,  # 1 rupee in paise
                'currency': 'INR',
                'receipt': 'test_receipt_123'
            })
            test_result = "✅ Connection successful"
        except Exception as e:
            test_result = f"❌ Error: {str(e)}"
    
    return f"""
    <h2>Razorpay Debug Information</h2>
    <p><strong>Razorpay Key ID:</strong> {RAZORPAY_KEY_ID[:20] + '...' if RAZORPAY_KEY_ID else 'Not set'}</p>
    <p><strong>Razorpay Key Secret:</strong> {'Set' if RAZORPAY_KEY_SECRET else 'Not set'}</p>
    <p><strong>Webhook Secret:</strong> {'Set' if RAZORPAY_WEBHOOK_SECRET else 'Not set'}</p>
    <p><strong>Status:</strong> {razorpay_status}</p>
    <p><strong>Connection Test:</strong> {test_result}</p>
    <hr>
    <a href="/buy_credits">Test Buy Credits</a><br>
    <a href="/">Back to Home</a>
    """

@app.route("/qr_code")
@login_required
def get_qr_code():
    uid = session["user_id"]
    conn = get_connection()
    cur = dict_cursor(conn)
    cur.execute("SELECT qr_code FROM users WHERE user_id=%s", (uid,))
    row = cur.fetchone()
    
    if not row or not row["qr_code"]:
        flash("QR code not generated yet. Upload a document first.")
        return redirect(url_for("dashboard"))
    
    qr_data = row["qr_code"]
    
    # Convert memoryview to bytes if needed
    if isinstance(qr_data, memoryview):
        qr_data = qr_data.tobytes()
    
    cur.close(); conn.close()
    
    # Create response to display QR code
    resp = make_response(qr_data)
    resp.headers.set("Content-Type", "image/png")
    resp.headers.set("Content-Disposition", "inline")
    return resp

@app.route("/admin")
@login_required
def admin_dashboard():
    """Main admin dashboard with comprehensive statistics"""
    # Check if current user is admin
    if not session.get('is_admin', False):
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Basic stats
        cur.execute("SELECT COUNT(*) as count FROM users")
        total_users = cur.fetchone()['count']
        
        cur.execute("SELECT SUM(amount) as total FROM transaction_historys WHERE status='paid'")
        total_revenue = cur.fetchone()['total'] or 0
        
        cur.execute("SELECT COUNT(*) as count FROM print_jobs WHERE status='pending'")
        active_print_jobs = cur.fetchone()['count']
        
        cur.execute("SELECT SUM(amount) as total FROM transaction_historys WHERE status='paid'")
        total_credits_sold = cur.fetchone()['total'] or 0
        
        # Advanced analytics
        
        # Daily statistics (today)
        cur.execute("""
            SELECT 
                COUNT(*) as daily_users,
                SUM(amount) as daily_revenue,
                COUNT(CASE WHEN status='paid' THEN 1 END) as daily_paid_transactions
            FROM transaction_historys 
            WHERE DATE(created_at) = CURRENT_DATE
        """)
        daily_stats = cur.fetchone()
        
        # Weekly statistics (last 7 days)
        cur.execute("""
            SELECT 
                COUNT(*) as weekly_users,
                SUM(amount) as weekly_revenue,
                COUNT(CASE WHEN status='paid' THEN 1 END) as weekly_paid_transactions
            FROM transaction_historys 
            WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
        """)
        weekly_stats = cur.fetchone()
        
        # Monthly statistics (last 30 days)
        cur.execute("""
            SELECT 
                COUNT(*) as monthly_users,
                SUM(amount) as monthly_revenue,
                COUNT(CASE WHEN status='paid' THEN 1 END) as monthly_paid_transactions
            FROM transaction_historys 
            WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
        """)
        monthly_stats = cur.fetchone()
        
        # Print jobs analytics
        cur.execute("""
            SELECT 
                COUNT(*) as total_print_jobs,
                COUNT(CASE WHEN DATE(requested_at) = CURRENT_DATE THEN 1 END) as daily_print_jobs,
                COUNT(CASE WHEN requested_at >= CURRENT_DATE - INTERVAL '7 days' THEN 1 END) as weekly_print_jobs,
                COUNT(CASE WHEN requested_at >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as monthly_print_jobs
            FROM print_jobs
        """)
        print_jobs_stats = cur.fetchone()
        
        # Top users by credits
        cur.execute("""
            SELECT u.user_id, u.user_name, u.user_email, u.credits, u.created_at,
                   COALESCE(SUM(th.amount), 0) as total_spent
            FROM users u
            LEFT JOIN transaction_historys th ON u.user_id = th.user_id AND th.status = 'paid'
            GROUP BY u.user_id, u.user_name, u.user_email, u.credits, u.created_at
            ORDER BY u.credits DESC 
            LIMIT 10
        """)
        top_users_by_credits = cur.fetchall()
        
        # Recent transactions
        cur.execute("""
            SELECT th.*, u.user_name, u.user_email as email 
            FROM transaction_historys th 
            JOIN users u ON th.user_id = u.user_id 
            ORDER BY th.created_at DESC 
            LIMIT 20
        """)
        recent_transactions = cur.fetchall()
        
        # Recent users
        cur.execute("""
            SELECT user_id, user_name, user_email as email, credits, created_at 
            FROM users 
            ORDER BY created_at DESC 
            LIMIT 15
        """)
        recent_users = cur.fetchall()
        
        # Print jobs by status
        cur.execute("""
            SELECT status, COUNT(*) as count
            FROM print_jobs
            GROUP BY status
            ORDER BY count DESC
        """)
        print_jobs_by_status = cur.fetchall()
        
        # Transaction status breakdown
        cur.execute("""
            SELECT status, COUNT(*) as count, SUM(amount) as total_amount
            FROM transaction_historys
            GROUP BY status
            ORDER BY count DESC
        """)
        transaction_status_breakdown = cur.fetchall()
        
        cur.close(); conn.close()
        
        stats = {
            'total_users': total_users,
            'total_revenue': total_revenue,
            'active_print_jobs': active_print_jobs,
            'total_credits_sold': total_credits_sold,
            'daily_stats': daily_stats,
            'weekly_stats': weekly_stats,
            'monthly_stats': monthly_stats,
            'print_jobs_stats': print_jobs_stats,
            'top_users_by_credits': top_users_by_credits,
            'print_jobs_by_status': print_jobs_by_status,
            'transaction_status_breakdown': transaction_status_breakdown
        }
        
        return render_template('admin_dashboard.html', 
                               stats=stats, 
                               recent_transactions=recent_transactions,
                               recent_users=recent_users)
                               
    except Exception as e:
        flash(f"Error loading admin dashboard: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route("/make_me_admin")
@login_required
def make_me_admin():
    """Route to make the current user an admin (for testing purposes)"""
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Make current user admin
        cur.execute("UPDATE users SET is_admin = TRUE WHERE user_id=%s", (session["user_id"],))
        conn.commit()
        
        # Update session
        session["is_admin"] = True
        
        cur.close(); conn.close()
        
        flash("✅ You are now an admin! You can access the admin dashboard.")
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        flash(f"Error making you admin: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route("/admin/add_credits", methods=["POST"])
@login_required
def admin_add_credits_post():
    """Admin route to add credits via POST"""
    # Check if current user is admin
    if not session.get('is_admin', False):
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('dashboard'))
    
    try:
        user_id = int(request.form.get('user_id', 0))
        credits = int(request.form.get('credits', 0))
        reason = request.form.get('reason', 'Admin addition')
        
        if user_id <= 0 or credits <= 0:
            flash("Invalid user ID or credits amount.")
            return redirect(url_for('admin_dashboard'))
        
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Get current credits
        cur.execute("SELECT credits, user_email FROM users WHERE user_id=%s", (user_id,))
        user_data = cur.fetchone()
        
        if not user_data:
            flash("User not found.")
            return redirect(url_for('admin_dashboard'))
        
        current_credits = user_data['credits']
        new_credits = current_credits + credits
        
        # Update user credits
        cur.execute("UPDATE users SET credits=%s WHERE user_id=%s", (new_credits, user_id))
        
        # Record transaction in transaction_historys table
        cur.execute("""
            INSERT INTO transaction_historys (user_id, amount, provider, status, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, credits, 'admin', 'paid', f'Admin: {reason}'))
        
        conn.commit()
        cur.close(); conn.close()
        
        flash(f"✅ Successfully added {credits} credits to user {user_data['user_email']}. New balance: {new_credits} credits.")
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        flash(f"Error adding credits: {str(e)}")
        return redirect(url_for('admin_dashboard'))

@app.route("/admin/add_credits/<int:user_id>/<int:credits>")
@login_required
def admin_add_credits(user_id, credits):
    """Admin route to manually add credits to a user's account"""
    # Check if current user is admin
    if not session.get('is_admin', False):
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Get current credits
        cur.execute("SELECT credits, user_email FROM users WHERE user_id=%s", (user_id,))
        user_data = cur.fetchone()
        
        if not user_data:
            flash("User not found.")
            return redirect(url_for('dashboard'))
        
        current_credits = user_data['credits']
        new_credits = current_credits + credits
        
        # Update user credits
        cur.execute("UPDATE users SET credits=%s WHERE user_id=%s", (new_credits, user_id))
        
        # Record transaction in transaction_historys table
        cur.execute("""
            INSERT INTO transaction_historys (user_id, amount, provider, status, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (user_id, credits, 'admin', 'paid', f'Admin added {credits} credits'))
        
        conn.commit()
        cur.close(); conn.close()
        
        flash(f"✅ Successfully added {credits} credits to user {user_data['user_email']}. New balance: {new_credits} credits.")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f"Error adding credits: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route("/add_credits", methods=["POST"])
@login_required
def add_credits():
    """Quick route to add credits for testing"""
    try:
        credits = int(request.form.get('credits', 0))
        if credits <= 0:
            flash("Invalid credits amount.")
            return redirect(url_for('dashboard'))
        
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Get current credits
        cur.execute("SELECT credits FROM users WHERE user_id=%s", (session["user_id"],))
        current_credits = cur.fetchone()["credits"]
        
        # Add credits
        new_credits = current_credits + credits
        cur.execute("UPDATE users SET credits=%s WHERE user_id=%s", (new_credits, session["user_id"]))
        
        # Record transaction
        cur.execute("""
            INSERT INTO transaction_historys (user_id, amount, provider, status, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (session["user_id"], credits, 'manual', 'paid', f'Manual addition of {credits} credits'))
        
        conn.commit()
        cur.close(); conn.close()
        
        flash(f"✅ Successfully added {credits} credits to your account. New balance: {new_credits} credits.")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f"Error adding credits: {str(e)}")
        return redirect(url_for('dashboard'))

# Quick payment routes for 50 and 100 rupee orders
@app.route("/pay/50")
@login_required
def pay_50_rupees():
    """Quick payment for 50 rupees (5000 paise)"""
    return create_payment_order(50, "Quick 50 Rupees Purchase")

@app.route("/pay/100")
@login_required
def pay_100_rupees():
    """Quick payment for 100 rupees (10000 paise)"""
    return create_payment_order(100, "Quick 100 Rupees Purchase")

@app.route("/pay/custom/<int:amount>/<int:credits>")
@login_required
def pay_custom_credits(amount, credits):
    """Custom payment where you can specify amount to pay and credits to receive"""
    return create_payment_order_with_credits(amount, credits, f"Custom Payment - {credits} Credits")

def create_payment_order(amount, description):
    """Helper function to create Razorpay order"""
    return create_payment_order_with_credits(amount, amount, description)

def create_payment_order_with_credits(amount, credits, description):
    """Helper function to create Razorpay order with specified credits"""
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        flash("Payment service is not configured. Please contact support.")
        return redirect(url_for("dashboard"))
    
    try:
        import razorpay
        client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        
        # Create order data
        order_data = {
            "amount": amount * 100,  # Convert to paise
            "currency": "INR",
            "receipt": f"receipt_{session['user_id']}_{int(time.time())}",
            "notes": {
                "user_id": session["user_id"],
                "description": description,
                "amount_rupees": amount,
                "credits": credits
            }
        }
        
        # Create order
        order = client.order.create(data=order_data)
        
        # Store transaction info in session
        trans_id = f"trans_{session['user_id']}_{int(time.time())}"
        session['current_transaction'] = {
            'order_id': order['id'],
            'amount': amount,
            'credits': credits,
            'trans_id': trans_id
        }
        
        return render_template("pay.html", 
                             order=order, 
                             amount=amount,
                             key_id=RAZORPAY_KEY_ID,
                             trans_id=trans_id)
        
    except Exception as e:
        flash(f"Error creating payment order: {str(e)}")
        return redirect(url_for("dashboard"))

@app.route("/payment/success")
@login_required
def payment_success():
    """Handle successful payment"""
    order_id = request.args.get('order_id')
    payment_id = request.args.get('payment_id')
    signature = request.args.get('signature')
    
    if not all([order_id, payment_id, signature]):
        flash("Invalid payment response.")
        return redirect(url_for("dashboard"))
    
    try:
        import razorpay
        client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        
        # Verify payment signature
        params_dict = {
            'razorpay_order_id': order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }
        
        client.utility.verify_payment_signature(params_dict)
        
        # Get transaction info from session
        trans_info = session.get('current_transaction', {})
        amount = trans_info.get('amount', 0)
        credits_to_add = trans_info.get('credits', amount)  # Use credits from session, fallback to amount
        
        # Debug logging
        print(f"Payment success - Session trans_info: {trans_info}")
        print(f"Payment success - Amount: {amount}, Credits to add: {credits_to_add}")
        
        # Update user credits in database
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Get current credits
        cur.execute("SELECT credits FROM users WHERE user_id=%s", (session["user_id"],))
        current_credits = cur.fetchone()["credits"]
        
        # Add credits
        new_credits = current_credits + credits_to_add
        
        cur.execute("UPDATE users SET credits=%s WHERE user_id=%s", (new_credits, session["user_id"]))
        
        # Record transaction in transaction_historys table
        cur.execute("""
            INSERT INTO transaction_historys (user_id, amount, provider, razorpay_order_id, razorpay_payment_id, razorpay_signature, status, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (session["user_id"], amount, 'razorpay', order_id, payment_id, signature, 'paid', f'Purchase of {credits_to_add} credits (paid ₹{amount})'))
        
        conn.commit()
        cur.close(); conn.close()
        
        # Clear transaction from session
        session.pop('current_transaction', None)
        
        return render_template("success.html",
                             payment_id=payment_id,
                             order_id=order_id,
                             amount=amount,
                             credits=new_credits,
                             credits_added=credits_to_add)
        
    except razorpay.errors.SignatureVerificationError:
        flash("Payment verification failed. Please contact support.")
        return redirect(url_for("dashboard"))
    except Exception as e:
        flash(f"Error processing payment: {str(e)}")
        return redirect(url_for("dashboard"))


# Route to promote user to admin (use carefully)
@app.route("/make_admin/<int:user_id>")
@login_required
def make_admin(user_id):
    """Promote a user to admin - use this route carefully to set up first admin"""
    # Only allow admin users to promote others to admin
    if not session.get('is_admin', False):
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('dashboard'))
        
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Check if user exists
        cur.execute("SELECT user_email FROM users WHERE user_id=%s", (user_id,))
        user_data = cur.fetchone()
        
        if not user_data:
            flash("User not found.")
            return redirect(url_for('dashboard'))
        
        # Promote to admin
        cur.execute("UPDATE users SET is_admin=TRUE WHERE user_id=%s", (user_id,))
        conn.commit()
        cur.close(); conn.close()
        
        flash(f"User {user_data['user_email']} has been promoted to admin.")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f"Error promoting user to admin: {str(e)}")
        return redirect(url_for('dashboard'))

# Route to regenerate all QR codes
@app.route("/regenerate_qr_codes")
@login_required
def regenerate_qr_codes():
    """Regenerate all QR codes with the correct port"""
    if not session.get('is_admin', False):
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('dashboard'))
        
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Get all users with quick_login_token
        cur.execute("SELECT user_id, quick_login_token FROM users WHERE quick_login_token IS NOT NULL")
        users = cur.fetchall()
        
        count = 0
        for user in users:
            token = user['quick_login_token']
            uid = user['user_id']
            
            # Generate new QR code with correct port
            import socket
            ip_address = socket.gethostbyname(socket.gethostname())
            qr_payload = f"http://{ip_address}:5001/quick_login/{token}"
            
            qr = qrcode.make(qr_payload)
            buf = io.BytesIO()
            qr.save(buf, format="PNG")
            qr_bytes = buf.getvalue()
            
            # Update QR code in database
            cur.execute(
                "UPDATE users SET qr_code=%s WHERE user_id=%s",
                (psycopg2.Binary(qr_bytes), uid)
            )
            count += 1
            
        conn.commit()
        cur.close(); conn.close()
        
        flash(f"Successfully regenerated {count} QR codes with the correct port.")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f"Error regenerating QR codes: {str(e)}")
        return redirect(url_for('dashboard'))

# Session manager routes
@app.route("/session_manager")
@login_required
def session_manager():
    """Session manager page for handling multi-tab sessions"""
    return render_template("session_manager.html")

# Ink Management Routes
@app.route("/admin/ink_changes", methods=["GET"])
@admin_required
def admin_ink_changes():
    """Admin ink change history page"""
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Get ink change history with admin user details
        cur.execute("""
            SELECT ich.*, u.user_name as admin_name, u.user_email as admin_email
            FROM ink_change_history ich
            JOIN users u ON ich.admin_user_id = u.user_id
            ORDER BY ich.change_date DESC, ich.created_at DESC
        """)
        ink_changes = cur.fetchall()
        
        # Get ink usage statistics
        cur.execute("SELECT * FROM get_ink_usage_stats()")
        usage_stats = cur.fetchall()
        
        # Get monthly costs for current year
        cur.execute("SELECT * FROM get_monthly_ink_costs()")
        monthly_costs = cur.fetchall()
        
        cur.close(); conn.close()
        
        return render_template("admin_ink_changes.html", 
                             ink_changes=ink_changes,
                             usage_stats=usage_stats,
                             monthly_costs=monthly_costs)
                             
    except Exception as e:
        flash(f"Error loading ink change history: {str(e)}")
        return redirect(url_for('admin_dashboard'))

@app.route("/admin/add_ink_change", methods=["POST"])
@admin_required
def admin_add_ink_change():
    """Admin route to add ink change record"""
    try:
        admin_user_id = session["user_id"]
        printer_name = request.form.get('printer_name', '').strip()
        ink_type = request.form.get('ink_type', '').strip()
        change_date = request.form.get('change_date')
        cost = float(request.form.get('cost', 0))
        notes = request.form.get('notes', '').strip()
        pages_printed_since_last_change = int(request.form.get('pages_printed_since_last_change', 0))
        estimated_pages_remaining = int(request.form.get('estimated_pages_remaining', 0))
        
        # Validate inputs
        if not printer_name or not ink_type or not change_date or cost <= 0:
            flash("Please fill all required fields with valid values.")
            return redirect(url_for('admin_ink_changes'))
        
        conn = get_connection()
        cur = dict_cursor(conn)
        
        # Insert ink change record
        cur.execute("""
            INSERT INTO ink_change_history 
            (admin_user_id, printer_name, ink_type, change_date, cost, notes, 
             pages_printed_since_last_change, estimated_pages_remaining)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (admin_user_id, printer_name, ink_type, change_date, cost, notes,
              pages_printed_since_last_change, estimated_pages_remaining))
        
        conn.commit()
        cur.close(); conn.close()
        
        flash(f"✅ Ink change recorded successfully for {printer_name} ({ink_type}). Cost: ₹{cost:.2f}")
        return redirect(url_for('admin_ink_changes'))
        
    except Exception as e:
        flash(f"Error recording ink change: {str(e)}")
        return redirect(url_for('admin_ink_changes'))

@app.route("/admin/export_csv/<data_type>")
@admin_required
def admin_export_csv(data_type):
    """Export various data types as CSV files"""
    try:
        conn = get_connection()
        cur = dict_cursor(conn)
        
        if data_type == "transactions":
            cur.execute("""
                SELECT 
                    th.trans_id,
                    u.user_name,
                    u.user_email,
                    th.amount,
                    th.provider,
                    th.status,
                    th.description,
                    th.created_at
                FROM transaction_historys th
                JOIN users u ON th.user_id = u.user_id
                ORDER BY th.created_at DESC
            """)
            data = cur.fetchall()
            filename = f"transactions_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            headers = ['Transaction ID', 'User Name', 'User Email', 'Amount (₹)', 'Provider', 'Status', 'Description', 'Created At']
            
        elif data_type == "users":
            cur.execute("""
                SELECT 
                    user_id,
                    user_name,
                    user_email,
                    credits,
                    created_at,
                    is_admin
                FROM users
                ORDER BY created_at DESC
            """)
            data = cur.fetchall()
            filename = f"users_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            headers = ['User ID', 'Name', 'Email', 'Credits', 'Created At', 'Is Admin']
            
        elif data_type == "print_jobs":
            cur.execute("""
                SELECT 
                    pj.job_id,
                    u.user_name,
                    u.user_email,
                    d.doc_name,
                    pj.printer,
                    pj.page_range,
                    pj.copies,
                    pj.duplex,
                    pj.status,
                    pj.credits_deducted,
                    pj.requested_at,
                    pj.printed_at,
                    pj.admin_notes
                FROM print_jobs pj
                JOIN users u ON pj.user_id = u.user_id
                JOIN documents d ON pj.doc_id = d.doc_id
                ORDER BY pj.requested_at DESC
            """)
            data = cur.fetchall()
            filename = f"print_jobs_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            headers = ['Job ID', 'User Name', 'User Email', 'Document', 'Printer', 'Page Range', 'Copies', 'Duplex', 'Status', 'Credits', 'Requested At', 'Printed At', 'Admin Notes']
            
        elif data_type == "ink_changes":
            cur.execute("""
                SELECT 
                    ich.change_id,
                    u.user_name as admin_name,
                    ich.printer_name,
                    ich.ink_type,
                    ich.change_date,
                    ich.cost,
                    ich.notes,
                    ich.pages_printed_since_last_change,
                    ich.estimated_pages_remaining,
                    ich.created_at
                FROM ink_change_history ich
                JOIN users u ON ich.admin_user_id = u.user_id
                ORDER BY ich.change_date DESC
            """)
            data = cur.fetchall()
            filename = f"ink_changes_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            headers = ['Change ID', 'Admin Name', 'Printer', 'Ink Type', 'Change Date', 'Cost (₹)', 'Notes', 'Pages Since Last', 'Est. Pages Remaining', 'Created At']
            
        else:
            flash("Invalid data type for export.")
            return redirect(url_for('admin_dashboard'))
        
        # Create CSV content
        import csv
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(headers)
        
        # Write data rows
        for row in data:
            # Convert datetime objects to strings and handle None values
            row_data = []
            for key in headers:
                # Map header names to database column names
                col_map = {
                    'Transaction ID': 'trans_id',
                    'User Name': 'user_name',
                    'User Email': 'user_email',
                    'Amount (₹)': 'amount',
                    'Provider': 'provider',
                    'Status': 'status',
                    'Description': 'description',
                    'Created At': 'created_at',
                    'User ID': 'user_id',
                    'Name': 'user_name',
                    'Email': 'user_email',
                    'Credits': 'credits',
                    'Created At': 'created_at',
                    'Is Admin': 'is_admin',
                    'Job ID': 'job_id',
                    'Document': 'doc_name',
                    'Printer': 'printer',
                    'Page Range': 'page_range',
                    'Copies': 'copies',
                    'Duplex': 'duplex',
                    'Requested At': 'requested_at',
                    'Printed At': 'printed_at',
                    'Admin Notes': 'admin_notes',
                    'Change ID': 'change_id',
                    'Admin Name': 'admin_name',
                    'Printer': 'printer_name',
                    'Ink Type': 'ink_type',
                    'Change Date': 'change_date',
                    'Cost (₹)': 'cost',
                    'Notes': 'notes',
                    'Pages Since Last': 'pages_printed_since_last_change',
                    'Est. Pages Remaining': 'estimated_pages_remaining'
                }
                
                db_key = col_map.get(key, key.lower().replace(' ', '_'))
                value = row.get(db_key, '')
                
                # Handle datetime objects
                if hasattr(value, 'strftime'):
                    value = value.strftime('%Y-%m-%d %H:%M:%S')
                elif value is None:
                    value = ''
                elif isinstance(value, bool):
                    value = 'Yes' if value else 'No'
                elif isinstance(value, (int, float)) and 'amount' in db_key or 'cost' in db_key:
                    value = f"{value:.2f}"
                
                row_data.append(str(value))
            
            writer.writerow(row_data)
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        
        cur.close(); conn.close()
        return response
        
    except Exception as e:
        flash(f"Error exporting CSV: {str(e)}")
        return redirect(url_for('admin_dashboard'))

@app.route("/api/session/status")
@login_required
def session_status():
    """API endpoint to check session status"""
    return jsonify({
        "valid": True,
        "user_id": session.get("user_id"),
        "last_activity": session.get("last_activity"),
        "user_email": session.get("user_email"),
        "is_admin": session.get("is_admin", False)
    })

@app.route("/api/session/keepalive", methods=["POST"])
@login_required
def session_keepalive():
    """Keep session alive - update last activity"""
    session["last_activity"] = datetime.now(timezone.utc).isoformat()
    return jsonify({"success": True, "message": "Session kept alive"})

@app.route("/api/session/terminate", methods=["POST"])
@login_required
def session_terminate():
    """Terminate all sessions for current user"""
    try:
        # Create a session termination token
        termination_token = f"terminate_{session['user_id']}_{int(time.time())}"
        
        # Store in session for other tabs to check
        session["session_terminated"] = termination_token
        session["termination_time"] = datetime.now(timezone.utc).isoformat()
        
        return jsonify({
            "success": True, 
            "message": "All sessions terminated",
            "token": termination_token
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ----- Run -----
if __name__ == "__main__":
    app.run(debug=True)
