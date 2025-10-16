import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")

    # Zoom
    ZOOM_CLIENT_ID = os.getenv("ZOOM_CLIENT_ID")
    ZOOM_CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET")
    ZOOM_ACCOUNT_ID = os.getenv("ZOOM_ACCOUNT_ID")
    ZOOM_TOKEN_URL = "https://zoom.us/oauth/token"
    ZOOM_API_BASE_URL = "https://api.zoom.us/v2"

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///zoom_phone.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    










