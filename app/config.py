import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    UPLOAD_FOLDER = 'app/static/reports'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max