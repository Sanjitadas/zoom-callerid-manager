from datetime import datetime
from extensions import db
from models import ActivityLog, AllowedUser
from flask import session, current_app
import pandas as pd
from zoom_api import update_line_key

# --- Imports for Robust API Calls (Retries & Token Refresh) ---
import time
import random
from settings import logger # Assuming logger is configured in settings
from zoom_token import get_access_token # Assuming get_access_token is available
# -------------------------------------------------------------

def parse_excel(file):
    """
    Reads an Excel/CSV file and returns a list of dicts with 'email' and 'caller_id'.
    Returns an empty list [] and logs an error on parsing failure.
    """
    try:
        # 1. Read the file based on extension
        if file.filename.endswith(".csv"):
            df = pd.read_csv(file)
        elif file.filename.endswith((".xlsx", ".xls")):
            df = pd.read_excel(file)
        else:
            logger.error(f"Unsupported file type uploaded: {file.filename}. Must be .csv, .xlsx, or .xls.")
            return []
            
        # 2. Standardize columns to lowercase
        df.columns = [c.lower() for c in df.columns]
        
        # 3. Validate required columns
        required_cols = ["email", "caller_id"]
        if not all(col in df.columns for col in required_cols):
            logger.error(f"File {file.filename} is missing required column headers. Required: {required_cols}. Found: {list(df.columns)}")
            return []
            
        # 4. Remove rows where 'email' or 'caller_id' are missing
        df = df.dropna(subset=required_cols)
        
        return df.to_dict(orient="records")
    
    except Exception as e:
        # Log a detailed error if pandas or file I/O fails
        logger.exception(f"Critical error parsing uploaded file {file.filename}. Check file integrity and format.")
        return []


def update_zoom_user(email, caller_id, max_retries=5, base_delay=1.0):
    """
    Wrapper for zoom_api.update_line_key with retries and token refresh.
    
    Returns the result dictionary: 
    {'status': 'success'/'failed', 'reason': 'message', 'extension': ..., 'line_key_id': ..., 'raw': ...}.
    
    The reason field examples:
    - Success: "Successfully updated"
    - Failed: "No response from Zoom API" or "Duplicate caller ID"
    """
    attempt, reason, raw = 0, None, None
    
    while attempt < max_retries:
        try:
            res = update_line_key(email, caller_id)
            raw = res
            status = res.get("status", "failed")
            reason = res.get("reason") or res.get("error")
            
            if status == "success":
                # Standardize the success reason as required
                return {
                    "status": "success", 
                    "reason": "Successfully updated",
                    "extension": res.get("extension"),
                    "line_key_id": res.get("line_key_id"),
                    "raw": res
                }

            # Handle Rate Limiting (429 or similar indicators)
            if reason and ("429" in str(reason) or "Rate limit" in str(reason) or "Too Many Requests" in str(reason)):
                delay = base_delay * (2 ** attempt) + random.uniform(0, 0.5)
                logger.warning("Rate limit hit for %s. Backing off %.2f sec (Attempt %d/%d)", email, delay, attempt + 1, max_retries)
                time.sleep(delay)
            
            # Refresh token on first failure attempt to handle expired tokens
            if attempt == 0 and status == "failed":
                try:
                    # Refresh token and try again
                    get_access_token()
                except Exception as e:
                    logger.warning("Token refresh failed for %s: %s", email, e)
            
            attempt += 1

        except Exception as e:
            # Catch unexpected Python errors (e.g., network timeout before response)
            logger.exception("update_zoom_user exception for %s: %s", email, e)
            return {
                "status": "failed", 
                "reason": f"Critical Python Error: {type(e).__name__}: {str(e)}", 
                "extension": None, 
                "line_key_id": None, 
                "raw": None
            }

    # If the loop finishes without success, return the last known reason (or generic fail message)
    return {
        "status": "failed", 
        "reason": reason or "Failed after retries. Last status reason: No response from Zoom API.", 
        "extension": None, 
        "line_key_id": None, 
        "raw": raw
    }


def log_activity(event_type, email=None, action=None, session_duration=None, **kwargs):
    try:
        email_val = email or kwargs.get("user_email") or session.get("user_email") or "unknown"
        action_val = action or kwargs.get("details") or kwargs.get("action") or ""
        duration_val = session_duration or kwargs.get("duration_seconds") or kwargs.get("session_duration")
        al = ActivityLog(
            event_type=event_type,
            email=email_val,
            action=action_val,
            timestamp=datetime.utcnow(),
            session_duration=duration_val
        )
        db.session.add(al)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Error logging activity: {e}")

def get_allowed_users_status():
    """
    Retrieves the list of all allowed users and calculates the online/offline count.
    
    Returns: Tuple (all_allowed_users, online_count, offline_count)
    """
    try:
        # Get all users
        all_users = AllowedUser.query.all()
        
        # Calculate online/offline counts
        online_count = AllowedUser.query.filter_by(is_online=True).count()
        offline_count = AllowedUser.query.filter_by(is_online=False).count()
        
        return all_users, online_count, offline_count
    except Exception as e:
        # Log the error safely
        if current_app:
            current_app.logger.error("get_allowed_users_status error: %s", e)
        return [], 0, 0
