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

    if not ACCESS_TOKEN or now >= EXPIRY:
        try:
            response = requests.post(
                TOKEN_URL,
                params={"grant_type": "account_credentials", "account_id": ACCOUNT_ID},
                auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET),
            )
            response.raise_for_status()
            data = response.json()
            ACCESS_TOKEN = data["access_token"]
            EXPIRY = now + data.get("expires_in", 3600) - 60  # fallback 1 hour
            print("🔑 Zoom access token refreshed successfully")
        except Exception as e:
            print(f"❌ Failed to get Zoom token: {e}")
            raise e

    return ACCESS_TOKEN


def get_headers():
    """
    Return request headers with valid access token.
    """
    return {"Authorization": f"Bearer {get_access_token()}"}


