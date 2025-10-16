# auth.py
from flask import request, session, redirect, url_for, flash, render_template, Blueprint
from datetime import datetime, timezone
from sqlalchemy import func
from extensions import db
from models import Admin, AllowedUser, ActivityLog

auth_bp = Blueprint("auth", __name__, template_folder="templates")

# ---------------------------------------------
# LOGIN
# ---------------------------------------------
@auth_bp.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email_input = (request.form.get('email') or '').strip().lower()
        password_input = (request.form.get('password') or '').strip()

        # try admin
        admin = Admin.query.filter(func.lower(Admin.email) == email_input).first()
        if admin and admin.password.strip() == password_input:
            session['user_email'] = admin.email
            session['role'] = 'admin'
            session['login_ts'] = datetime.utcnow().isoformat()
            # log
            db.session.add(ActivityLog(email=admin.email, action="Admin logged in", event_type="LOGIN", timestamp=datetime.utcnow()))
            db.session.commit()
            flash("✅ Logged in as Admin.", "success")
            return redirect(url_for('main.index'))

        user = AllowedUser.query.filter(func.lower(AllowedUser.email) == email_input).first()
        if user and user.password.strip() == password_input:
            session['user_email'] = user.email
            session['role'] = 'user'
            session['login_ts'] = datetime.utcnow().isoformat()
            db.session.add(ActivityLog(email=user.email, action="Allowed user logged in", event_type="LOGIN", timestamp=datetime.utcnow()))
            db.session.commit()
            flash("✅ Logged in successfully.", "success")
            # Allowed users must be redirected directly to bulk update
            return redirect(url_for('main.bulk_update'))

        flash("Invalid credentials.", "danger")
        return redirect(url_for('auth.login'))

    # GET -> render login page
    return render_template('login.html')
# ---------------------------------------------
# LOGOUT
# ---------------------------------------------
from datetime import datetime, timezone

@auth_bp.route("/logout")
def logout():
    email = session.get("user_email", "Unknown")
    role = session.get("role", "user")
    login_time = session.get("login_ts")

    session_duration = None
    if login_time:
        # If login_time was stored as string, parse it
        if isinstance(login_time, str):
            try:
                login_time = datetime.fromisoformat(login_time)
            except Exception:
                login_time = None

        if login_time:
            # Make login_time UTC-aware if naive
            if login_time.tzinfo is None:
                login_time = login_time.replace(tzinfo=timezone.utc)

            # Calculate session duration
            delta = datetime.now(timezone.utc) - login_time
            session_duration = str(delta).split(".")[0]  # format HH:MM:SS

    # Log logout activity
    log = ActivityLog(
        email=email,
        action=f"{role.capitalize()} logged out",
        event_type="LOGOUT",
        timestamp=datetime.now(timezone.utc),
        session_duration=session_duration
    )
    db.session.add(log)
    db.session.commit()

    # Clear session
    session.clear()
    flash("👋 Logged out successfully.", "success")
    return redirect(url_for("auth.login"))























