from datetime import datetime
from extensions import db
from models import ActivityLog
from flask import session, current_app
import pandas as pd
from zoom_api import update_line_key

def parse_excel(file):
    """
    Reads an Excel/CSV file and returns a list of dicts with 'email' and 'caller_id'.
    """
    if file.filename.endswith(".csv"):
        df = pd.read_csv(file)
    else:
        df = pd.read_excel(file)
    df.columns = [c.lower() for c in df.columns]
    df = df.dropna(subset=["email", "caller_id"])
    return df.to_dict(orient="records")

def update_zoom_user(email, caller_id):
    """
    Wrapper for zoom_api.update_line_key
    Returns True if success, else False
    """
    result = update_line_key(email, caller_id)
    if result["status"] == "success":
        return True
    else:
        # Include reason in exception for logging
        raise Exception(result.get("reason", "Unknown error"))



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
        current_app.logger.exception(
            "log_activity error: %s | event=%s email=%s action=%s kwargs=%s",
            e, event_type, email, action, kwargs
        )
