# zoom_api.py
import requests
import pandas as pd
import time
from zoom_token import get_headers, BASE_URL

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

def _request_with_retry(method, url, **kwargs):
    """
    Helper function to handle Zoom API requests with retries on failure.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, **kwargs)
            if resp.status_code in (200, 204):
                return resp
            elif resp.status_code == 429:
                wait = int(resp.headers.get("Retry-After", RETRY_DELAY))
                print(f"⚠️ Rate limit reached. Retrying in {wait} seconds...")
                time.sleep(wait)
            else:
                resp.raise_for_status()
        except Exception as e:
            if attempt < MAX_RETRIES:
                print(f"⚠️ Attempt {attempt} failed: {e}. Retrying in {RETRY_DELAY}s...")
                time.sleep(RETRY_DELAY)
            else:
                print(f"❌ Failed after {MAX_RETRIES} attempts: {e}")
                return None
    return None

def update_line_key(user_email: str, caller_id: str):
    """
    Updates the primary outbound caller ID for a Zoom user (single line key update).
    Returns structured response.
    """
    try:
        # 1. Get user info by email
        url_user = f"{BASE_URL}/users/{user_email}"
        resp = _request_with_retry("GET", url_user, headers=get_headers())
        if not resp:
            return {"status": "failed", "reason": "No response from Zoom API", "response": None}

        user = resp.json()
        user_id = user.get("id")
        if not user_id:
            return {"status": "failed", "reason": "User not found", "response": user}

        # 2. Get list of phone numbers / line keys
        url_numbers = f"{BASE_URL}/phone/users/{user_id}/numbers"
        resp = _request_with_retry("GET", url_numbers, headers=get_headers())
        if not resp:
            return {"status": "failed", "reason": "No response from Zoom API", "response": None}

        numbers = resp.json().get("numbers", [])
        if not numbers:
            return {"status": "failed", "reason": "No phone numbers assigned", "response": numbers}

        # Update first main line key (usually primary)
        line_key_id = numbers[0]["id"]
        url_update = f"{BASE_URL}/phone/users/{user_id}/line_keys/{line_key_id}"
        payload = {
            "caller_id_name": user_email.split("@")[0],
            "caller_id_number": caller_id
        }

        resp = _request_with_retry("PATCH", url_update, json=payload, headers=get_headers())
        if not resp:
            return {"status": "failed", "reason": "No response from Zoom API", "response": None}

        response_data = {}
        if resp.content:
            try:
                response_data = resp.json()
            except:
                response_data = {}

        return {"status": "success", "extension": numbers[0].get("extension_number"),
                "line_key_id": line_key_id, "response": response_data}

    except Exception as e:
        return {"status": "failed", "reason": str(e), "response": None}

def bulk_update_line_keys(file_path: str, email_column: str = "email", caller_id_column: str = "caller_id"):
    """
    Bulk update Zoom users' caller IDs from an Excel/CSV file.
    Expects columns: email, caller_id
    Returns list of results per user.
    """
    results = []

    # Load file
    if file_path.endswith(".csv"):
        df = pd.read_csv(file_path)
    else:
        df = pd.read_excel(file_path)

    df.columns = [c.lower() for c in df.columns]  # normalize columns

    for index, row in df.iterrows():
        try:
            email = str(row.get(email_column.lower(), "")).strip()
            caller_id = str(row.get(caller_id_column.lower(), "")).strip()
            if email and caller_id:
                print(f"🔄 Updating {email} to caller ID {caller_id}...")
                result = update_line_key(email, caller_id)
            else:
                result = {"status": "failed", "reason": "Missing email or caller_id", "response": None}
        except Exception as e:
            result = {"status": "failed", "reason": str(e), "response": None}

        results.append({"email": email, "caller_id": caller_id, **result})

    return results





