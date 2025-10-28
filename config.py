# config.py
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Database configuration - Railway only (no local fallback)
DATABASE_URL = os.getenv("DATABASE_URL")

# Parse Railway DATABASE_URL (required for Railway deployment)
if DATABASE_URL:
    # Railway provides DATABASE_URL in format: postgresql://user:password@host:port/database
    import urllib.parse
    parsed = urllib.parse.urlparse(DATABASE_URL)
    DB_NAME = parsed.path[1:]  # Remove leading '/'
    DB_USER = parsed.username
    DB_PASSWORD = parsed.password
    DB_HOST = parsed.hostname
    DB_PORT = parsed.port or 5432
else:
    # No local fallback - Railway database is required
    raise ValueError("DATABASE_URL environment variable is required for Railway deployment. Please set your Railway database connection string.")

# Flask secret key
SECRET_KEY = os.getenv("SECRET_KEY", "fd7785a191da051e2d864b4910f7531480886253eb97bc99a7876189555eb817")

# Printer configuration
DEFAULT_PRINTER = os.getenv("DEFAULT_PRINTER", "auto")
PRINT_DPI = int(os.getenv("PRINT_DPI", "300"))

# Server configuration
SERVER_HOST = os.getenv("SERVER_HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("SERVER_PORT", "5001"))

# Razorpay (for future use)
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")

# OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "808146626909-aaokorph2nd0ul0g1l957p7dh3s2535n.apps.googleusercontent.com")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")  # Don't store secrets in code, use .env file
MICROSOFT_CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID", "")
MICROSOFT_CLIENT_SECRET = os.getenv("MICROSOFT_CLIENT_SECRET", "")

# Postmark Email Configuration
POSTMARK_API_TOKEN = os.getenv("POSTMARK_API_TOKEN", "")
POSTMARK_SENDER_EMAIL = os.getenv("POSTMARK_SENDER_EMAIL", "secureprintingsystem@gmail.com")
POSTMARK_SERVER_TOKEN = os.getenv("POSTMARK_SERVER_TOKEN", "")

# Flask-Mail Configuration (Legacy - will be replaced by Postmark)
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() == "true"
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "secureprintingsystem@gmail.com")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# Extended file format support
ALLOWED_EXTENSIONS = {
    # Documents
    "pdf", "docx", "doc",
    # Images
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "webp"
}
