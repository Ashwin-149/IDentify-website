import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SUPABASE_URL = os.environ.get('SUPABASE_URL') or 'https://your-project-id.supabase.co'
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY') or 'your-anon-key'
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or 'admin123'
    EVENT_PASSWORD = os.environ.get('EVENT_PASSWORD') or 'event123'
    UPLOAD_FOLDER = 'uploads'
    EVENTS_BUCKET = "events"  # storage bucket name
    ADMIN_REGISTRATION_CODE = os.environ.get('ADMIN_REGISTRATION_CODE') or 'RFID'
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 10MB max file size
    EVENT_ADMIN_PASSWORD = "small"  # temp password
    SITE_NAME = "Your Club" #temp
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)  # session hard timeout
    REMEMBER_COOKIE_DURATION = timedelta(days=7)  # if you use remember=True at login
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # In production:
    # SESSION_COOKIE_SECURE = True
