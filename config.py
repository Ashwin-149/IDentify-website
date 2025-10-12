import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    SUPABASE_URL = os.environ.get('SUPABASE_URL') or 'https://your-project-id.supabase.co'
    SUPABASE_KEY = os.environ.get('SUPABASE_KEY') or 'your-anon-key'
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or 'admin123'
    EVENT_PASSWORD = os.environ.get('EVENT_PASSWORD') or 'event123'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
