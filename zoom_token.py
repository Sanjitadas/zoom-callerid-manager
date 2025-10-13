# zoom_token.py
import os
import time
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

ACCOUNT_ID = os.getenv("ZOOM_ACCOUNT_ID")
CLIENT_ID = os.getenv("ZOOM_CLIENT_ID")
CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET")

BASE_URL = "https://api.zoom.us/v2"
TOKEN_URL = "https://zoom.us/oauth/token"

# Cache token in memory
ACCESS_TOKEN = None
EXPIRY = 0

def get_access_token():
    """
    Get or refresh Zoom OAuth access token using Account Credentials grant type.
    Automatically refreshes before expiry.
    """
    global ACCESS_TOKEN, EXPIRY
    now = time.time()

    # Refresh if token missing or expired
    if not ACCESS_TOKEN or now >= EXPIRY:
        response = requests.post(
            TOKEN_URL,
            params={"grant_type": "account_credentials", "account_id": ACCOUNT_ID},
            auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET),
        )
        response.raise_for_status()
        data = response.json()

        ACCESS_TOKEN = data["access_token"]
        # Refresh 1 minute before expiry
        EXPIRY = now + data["expires_in"] - 60  

        print("🔑 Zoom access token refreshed successfully")

    return ACCESS_TOKEN

def get_headers():
    """
    Return request headers with valid access token.
    """
    return {"Authorization": f"Bearer {get_access_token()}"}


