# zoom_api.py
import requests
import time
import random
import json
# Import necessary components from the zoom_token file
from zoom_token import get_access_token, BASE_URL 
# Assuming you have a 'logger' configured in settings.py
from settings import logger 

# --- Helper Functions (Simulated Zoom Lookups) ---

def get_zoom_user_id(user_email):
    """
    Fetches the Zoom User ID from an email. This ID is required for the URL.
    In a real application, this calls GET /users?status=active&email={email}.
    """
    token = get_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    
    # Zoom endpoint to get user details by email
    # Zoom often uses the email as a path variable, but fetching the internal ID
    # is safer for subsequent calls. We use the email/ID directly here as Zoom
    # often allows it for the path, or the calling code already provides the ID.
    lookup_url = f"{BASE_URL}/users/{user_email}"
    try:
        response = requests.get(lookup_url, headers=headers)
        response.raise_for_status()
        user_data = response.json()
        # Return the Zoom User ID if found, otherwise the email (Zoom often accepts the email)
        return user_data.get('id', user_email) 
    except Exception as e:
        logger.warning(f"Failed to fetch Zoom User ID for {user_email}. Falling back to email/ID. Error: {e}")
        return user_email


# --- Core Update Function (Fix for 400 Error) ---

def update_line_key(user_email, new_caller_id):
    """
    Updates the outbound caller ID for a Zoom Phone user with retry logic.
    
    CRITICAL FIX: Uses the 'json' parameter in requests.patch to fix the 
    'Request Body should be a valid JSON object' (Error 400) issue.
    """
    max_retries = 3
    
    # Step 1: Get Zoom User ID (Ensure we use the correct identifier for the URL)
    # The actual user ID from the log is what we need in the URL path: -0lqj-mPTiqVE0uLuNA_eA
    zoom_user_id = get_zoom_user_id(user_email)
    
    # Step 2: Construct the API URL
    url = f"{BASE_URL}/phone/users/{zoom_user_id}/settings"
    
    # Step 3: Determine the payload (This is the standard structure for Caller ID update)
    # NOTE: 'external_id' should ideally be the Zoom Phone Number ID, not the number string. 
    # For now, we use the number, but be aware this may cause a different API error later if 
    # Zoom's API requires the internal ID.
    payload = {
        "caller_id": {
            "external_id": new_caller_id, 
            "display_external_caller_id": True
        }
    }
    
    logger.info(f"Attempting update for {user_email} ({zoom_user_id}) with payload: {json.dumps(payload)}")

    for attempt in range(1, max_retries + 1):
        try:
            token = get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }

            # --- CRITICAL FIX: Use the 'json' parameter! ---
            response = requests.patch(
                url,
                headers=headers,
                json=payload # <-- THIS FIXES THE 'Request Body should be a valid JSON object'
            )
            
            # Check for API success (204 No Content is common for PATCH/PUT updates)
            if response.status_code in [200, 204]:
                logger.info(f"✅ Update successful for {user_email} on attempt {attempt}.")
                return {"status": "success", "reason": "Caller ID updated successfully."}
            
            # Check for other HTTP errors (4xx or 5xx)
            response.raise_for_status()
            
        except requests.exceptions.HTTPError as e:
            # Extract error message from response text if available
            error_details = response.json().get('message', response.text) if response.text else 'Unknown HTTP Error'
            logger.error(f"❌ API Error {response.status_code} on attempt {attempt}: {error_details}")
            
            if attempt < max_retries:
                # Exponential backoff with jitter
                retry_in = 2 ** attempt + random.uniform(0, 1) 
                logger.warning(f"⚠️ Attempt {attempt} failed: {e}. Retrying in {retry_in:.1f}s...")
                time.sleep(retry_in)
            else:
                logger.error(f"❌ Failed after {max_retries} attempts: {e}")
                return {"status": "failed", "reason": f"API Error {response.status_code}: {error_details}"}
                
        except requests.exceptions.RequestException as e:
            # Catch connection or timeout errors
            logger.error(f"❌ Connection Error on attempt {attempt}: {e}")
            if attempt < max_retries:
                retry_in = 2 ** attempt + random.uniform(0, 1)
                logger.warning(f"⚠️ Attempt {attempt} failed: Connection issue. Retrying in {retry_in:.1f}s...")
                time.sleep(retry_in)
            else:
                logger.error(f"❌ Failed after {max_retries} attempts: Connection error.")
                return {"status": "failed", "reason": f"Connection Error: {e}"}
                
    # Fallback return
    return {"status": "failed", "reason": "Failed after all retries (check logs for details)."}








