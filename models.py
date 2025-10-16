# models.py
from flask_login import UserMixin
from datetime import datetime
from extensions import db

# ------------------------
# Admin Model
# ------------------------
class Admin(UserMixin, db.Model):
    __tablename__ = "admins"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)   # PLAIN TEXT
    default_password = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------------
# Allowed Users
# ------------------------
class AllowedUser(UserMixin, db.Model):
    __tablename__ = "allowed_users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)   # PLAIN TEXT
    default_password = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_online = db.Column(db.Boolean, default=False)
    
# CallerIDUpdate (Single)
class CallerIDUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.String(50))
    extension = db.Column(db.String(50))
    caller_id_name = db.Column(db.String(100))
    caller_id_number = db.Column(db.String(50))
    status = db.Column(db.String(20), nullable=False) 
    reason = db.Column(db.String(255))                # New column for failure reason
    updated_by = db.Column(db.String(150))
    update_type = db.Column(db.String(1), default='S') # 'S' for Single
    updated_ts = db.Column(db.DateTime, default=datetime.utcnow)

# BulkUpdateLog
class BulkUpdateLog(db.Model):
    __tablename__ = "bulk_update_log"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    old_caller_id = db.Column(db.String(20))
    new_caller_id = db.Column(db.String(20))
    reason = db.Column(db.String(255))                # Optional
    updated_by = db.Column(db.String(150))
    update_type = db.Column(db.String(1), default='B') # 'B' for Bulk
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50))

# ------------------------
# GLOBAL ACTIVITY LOG (LOGIN / LOGOUT / ADMIN ACTIONS)
# ------------------------
class ActivityLog(db.Model):
    __tablename__ = "activity_log"
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    action = db.Column(db.String(100), nullable=False)  # LOGIN / LOGOUT / UPDATE / ADD_USER etc.
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    session_duration = db.Column(db.String(50), nullable=True)  # For logout only

    def __repr__(self):
        return f"<ActivityLog {self.email} - {self.action}>"
















