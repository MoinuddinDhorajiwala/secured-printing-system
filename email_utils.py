# email_utils.py
import postmarker
from postmarker.core import PostmarkClient
from config import POSTMARK_API_TOKEN, POSTMARK_SENDER_EMAIL
import datetime
from datetime import timedelta
import random

class PostmarkEmailService:
    def __init__(self):
        self.client = PostmarkClient(server_token=POSTMARK_API_TOKEN)
        self.sender_email = POSTMARK_SENDER_EMAIL
    
    def send_otp_email(self, recipient_email, otp, purpose="verification"):
        """Send OTP email using Postmark"""
        try:
            if purpose == "password_reset":
                subject = "Secure Printing System - Password Reset Code"
                body = f"""Hello,

Your password reset code for Secure Printing System is: {otp}

This code is valid for 10 minutes.

If you didn't request a password reset, please ignore this email.

Best regards,
Secure Printing System Team"""
            else:
                subject = "Secure Printing System - OTP Verification"
                body = f"""Hello,

Your OTP for Secure Printing System is: {otp}

This OTP is valid for 10 minutes.

If you didn't request this, please ignore this email.

Best regards,
Secure Printing System Team"""
            
            response = self.client.emails.send(
                From=self.sender_email,
                To=recipient_email,
                Subject=subject,
                TextBody=body
            )
            
            print(f"Postmark email sent successfully: {response}")
            return True
            
        except Exception as e:
            print(f"Error sending Postmark email: {e}")
            return False
    
    def send_username_change_email(self, recipient_email, new_username, otp):
        """Send username change verification email using Postmark"""
        try:
            subject = "Username Change Verification - Secure Printing System"
            body = f"""Hello,

You have requested to change your username to: {new_username}

Your verification code is: {otp}

This code will expire in 5 minutes.

If you did not request this change, please ignore this email.

Best regards,
Secure Printing System"""
            
            response = self.client.emails.send(
                From=self.sender_email,
                To=recipient_email,
                Subject=subject,
                TextBody=body
            )
            
            print(f"Postmark username change email sent successfully: {response}")
            return True
            
        except Exception as e:
            print(f"Error sending Postmark username change email: {e}")
            return False
    
    def send_general_email(self, recipient_email, subject, body):
        """Send general email using Postmark"""
        try:
            response = self.client.emails.send(
                From=self.sender_email,
                To=recipient_email,
                Subject=subject,
                TextBody=body
            )
            
            print(f"Postmark general email sent successfully: {response}")
            return True
            
        except Exception as e:
            print(f"Error sending Postmark general email: {e}")
            return False

# Global email service instance
email_service = PostmarkEmailService()

# OTP Storage (in production, use Redis or database)
otp_storage = {}

def generate_otp():
    """Generate 6-digit OTP"""
    return str(random.randint(100000, 999999))

def store_otp(email, otp, expiration_minutes=10):
    """Store OTP with expiration time"""
    otp_storage[email] = {
        'otp': otp,
        'expires_at': datetime.datetime.utcnow() + timedelta(minutes=expiration_minutes)
    }

def verify_otp(email, otp):
    """Verify OTP and check expiration"""
    if email not in otp_storage:
        return False
    
    stored_data = otp_storage[email]
    
    # Check if OTP has expired
    if datetime.datetime.utcnow() > stored_data['expires_at']:
        del otp_storage[email]
        return False
    
    # Check if OTP matches
    if stored_data['otp'] == otp:
        del otp_storage[email]
        return True
    
    return False