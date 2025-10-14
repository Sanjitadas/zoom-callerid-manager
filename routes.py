# routes.py
"""
Production-ready Routes for Zoom Phone Caller ID Manager (Activity logging + Edit features)

Notes:
- This routes.py assumes models.py defines CallerIDUpdate.updated_ts (datetime) and
  BulkUpdateLog.timestamp (datetime) as in your models.py.
- It uses a flexible log_activity(...) helper that accepts legacy kwargs.
"""

from flask import (
    render_template, redirect, url_for, flash, request,
    session, jsonify, send_file, Blueprint, current_app
)
from functools import wraps
from extensions import db
from models import Admin, AllowedUser, CallerIDUpdate, BulkUpdateLog, ActivityLog
import pandas as pd
import io
from datetime import datetime, timedelta
import traceback
from sqlalchemy import func
import time, random, os
from zoom_api import update_line_key
from zoom_token import get_access_token
from settings import logger  # use single logger from settings
from utils import log_activity, parse_excel, update_zoom_user

main_bp = Blueprint("main", __name__)

# ---------------- Helpers / Decorators ----------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        if not session.get("user_email"):
            flash("⚠️ Please log in first.", "warning")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            flash("❌ Admins only.", "danger")
            # non-admins go to bulk_update page (allowed users)
            return redirect(url_for("main.bulk_update"))
        return f(*args, **kwargs)
    return decorated

def _interpret_zoom_result(res):
    """
    Normalize the zoom_api.update_line_key return into a 5-tuple:
    (success(bool), reason(str|None), extension(str|None), line_key_id(str|None), raw(dict|str|None))
    """
    if res is None:
        return False, "no_response", None, None, None
    if isinstance(res, bool):
        return (True, None, None, None, None) if res else (False, "failed_no_detail", None, None, None)
    try:
        status = res.get("status")
        reason = res.get("reason") or res.get("error") or None
        extension = res.get("extension")
        line_key_id = res.get("line_key_id")
        raw = res.get("response") or res.get("raw") or res
        success = (status == "success")
        return success, reason, extension, line_key_id, raw
    except Exception:
        return False, "invalid_zoom_response_structure", None, None, res
    
def get_allowed_users_status():
    allowed_users = AllowedUser.query.order_by(AllowedUser.email.asc()).all()
    online = [u.email for u in allowed_users if u.is_online]   # assuming AllowedUser has is_online column
    offline = [u.email for u in allowed_users if not u.is_online]
    return allowed_users, online, offline

# ---------------- Local log_activity (flexible signature) ----------------
def safe_update_line_key(email, caller_id, max_retries=5, base_delay=1.0):
    attempt = 0
    reason = None
    extension = None
    line_key_id = None
    raw = None
    while attempt < max_retries:
        try:
            res = update_line_key(email, caller_id)
            success = False
            try:
                status = res.get("status")
                reason = res.get("reason") or res.get("error")
                extension = res.get("extension")
                line_key_id = res.get("line_key_id")
                success = status == "success"
            except Exception:
                reason = "invalid_zoom_response"

            if success:
                return {"success": True, "reason": None, "extension": extension, "line_key_id": line_key_id, "raw": res}

            if reason and "429" in str(reason):
                delay = base_delay * (2 ** attempt) + random.uniform(0, 0.5)
                logger.warning("Rate limit hit for %s. Backing off %.2f sec", email, delay)
                time.sleep(delay)

            if attempt == 0:
                try:
                    get_access_token()
                except Exception as e:
                    logger.warning("Token refresh failed: %s", e)
            attempt += 1
        except Exception as e:
            logger.exception("safe_update_line_key exception: %s", e)
            return {"success": False, "reason": str(e), "extension": None, "line_key_id": None, "raw": None}
    return {"success": False, "reason": reason or "failed_after_retries", "extension": extension, "line_key_id": line_key_id, "raw": raw}

# ---------------- Pagination Helper ----------------
def paginate_query(query, page, per_page=20):
    page = max(int(page), 1)
    per_page = max(int(per_page), 5)
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    return items, total, page, per_page

# ---------------- Session / Bulk Helpers ----------------
SESSION_BULK_KEY = "bulk_data"
SESSION_LAST_UPDATE_TS = "bulk_last_update_ts"
SESSION_BULK_DOWNLOADED = "SESSION_BULK_DOWNLOADED"
STALE_MINUTES = 10

def cleanup_bulk_session():
    for k in [SESSION_BULK_KEY, SESSION_LAST_UPDATE_TS, SESSION_BULK_DOWNLOADED]:
        session.pop(k, None)
    session.modified = True

def is_bulk_session_stale():
    ts = session.get(SESSION_LAST_UPDATE_TS)
    if not ts:
        return True
    try:
        dt = datetime.fromisoformat(ts)
    except Exception:
        return True
    return datetime.utcnow() - dt > timedelta(minutes=STALE_MINUTES)

# ---------------- Render tables ----------------
def render_table(table_type):
    if table_type == "bulk":
        data = session.get("bulk_data", [])
        return render_template("partials/bulk_table.html", uploaded_data=data[:1000])
    elif table_type == "callerid":
        updates = CallerIDUpdate.query.order_by(CallerIDUpdate.updated_ts.desc()).limit(1000).all()
        return render_template("partials/callerid_updates_table.html", updates=updates)
    elif table_type == "allowed":
        users = AllowedUser.query.order_by(AllowedUser.created_at.desc()).all()
        return render_template("partials/allowed_users_table.html", allowed_users=users)
    elif table_type == "admins":
        admins = Admin.query.order_by(Admin.created_at.desc()).all()
        return render_template("partials/admins_table.html", admins=admins)
    return ""

# ---------------- Dashboard Routes ----------------
@main_bp.route("/")
@login_required
@admin_required
def index():
    total_allowed_users = AllowedUser.query.count()
    total_admins = Admin.query.count()
    total_callerid_updates = CallerIDUpdate.query.count()

    # fetch latest 20 updates for dashboard
    updates = CallerIDUpdate.query.order_by(CallerIDUpdate.updated_ts.desc()).limit(20).all()
    dashboard_updates = []
    for u in updates:
        # determine if bulk/single
        bulk_log = BulkUpdateLog.query.filter_by(email=u.user_id, timestamp=u.updated_ts).first()
        update_type = "B" if bulk_log else "S"
        dashboard_updates.append({
            "time": u.updated_ts.strftime("%Y-%m-%d %H:%M:%S"),
            "user": u.updated_by,
            "update_type": update_type
        })
    allowed_users, online, offline = get_allowed_users_status()
    log_activity("VIEW_DASHBOARD", action="Accessed admin dashboard")
    return render_template(
        "index.html",
        total_allowed_users=total_allowed_users,
        total_admins=total_admins,
        total_callerid_updates=total_callerid_updates,
        dashboard_updates=dashboard_updates,
        allowed_users=allowed_users,
        online_count=len(online),
        offline_count=len(offline)
    )

@main_bp.route("/activity_logs")
@login_required
@admin_required
def activity_logs():
    try:
        # Fetch all logs ordered by timestamp desc
        logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
        logger.info("Activity logs viewed by admin")
        return render_template("activity_logs.html", logs=logs)
    except Exception as e:
        logger.exception("Error loading activity logs: %s", e)
        flash("Error loading activity logs", "danger")
        return redirect(url_for("dashboard"))
    
@main_bp.route("/bulk_update", methods=["GET", "POST"])
@login_required
def bulk_update():
    success_updates = []
    failed_updates = []
    excel_data = None

    if request.method == "POST":
        file = request.files.get("file")
        if file:
            excel_data = parse_excel(file)
            for row in excel_data:
                email = row.get("email")
                caller_id = row.get("caller_id")
                try:
                    update_zoom_user(email, caller_id)
                    success_updates.append(email)
                    log_activity(
                        event_type="bulk_update",
                        email=session.get("user_email"),
                        action=f"Successfully updated caller ID for {email} → {caller_id}"
                    )
                except Exception as e:
                    failed_updates.append({"email": email, "error": str(e)})
                    log_activity(
                        event_type="bulk_update_error",
                        email=session.get("user_email"),
                        action=f"Failed to update {email}: {str(e)}"
                    )
    # Always fetch latest updates for table display
   # Fetch latest 1000 updates from DB
    updates = CallerIDUpdate.query.order_by(CallerIDUpdate.updated_ts.desc()).limit(1000).all()
    uploaded_data = [
     {
        "email": u.user_id,
        "outbound_caller_id": u.caller_id_number,
        "status": u.status,
        "reason": u.reason,
        "updated_by": u.updated_by,
        "updated_ts": u.updated_ts.strftime("%Y-%m-%d %H:%M:%S") if u.updated_ts else "-"
     } for u in updates
   ]

    return render_template(
    "bulk_update.html",
    uploaded_data=uploaded_data,   # latest DB updates
    success=success_updates,
    failed=failed_updates
)
@main_bp.route("/ajax/refresh_dashboard", methods=["GET"])
@login_required
@admin_required
def ajax_refresh_dashboard():
    # Fetch last 10 single updates
    single_updates = CallerIDUpdate.query.order_by(CallerIDUpdate.updated_ts.desc()).limit(10).all()

    # Fetch last 10 bulk updates
    bulk_updates = BulkUpdateLog.query.order_by(BulkUpdateLog.timestamp.desc()).limit(10).all()

    # Combine and mark type
    recent_updates = []

    # Single updates
    for u in single_updates:
        recent_updates.append({
            "updated_ts": u.updated_ts,
            "updated_by": u.updated_by,
            "caller_id_number": u.caller_id_number,
            "is_single": True,
            "is_bulk": False
        })

    # Bulk updates
    for b in bulk_updates:
        # Check if user already has a single update at same timestamp
        is_both = any(s["updated_by"]==b.email and s["updated_ts"]==b.timestamp for s in recent_updates)
        recent_updates.append({
            "updated_ts": b.timestamp,
            "updated_by": b.email,
            "caller_id_number": b.new_caller_id,
            "is_single": not is_both,
            "is_bulk": True
        })

    # Sort combined list by time descending
    recent_updates.sort(key=lambda x: x["updated_ts"], reverse=True)

    # Limit to 10
    recent_updates = recent_updates[:10]

    # Total updates count
    total_callerid_updates = CallerIDUpdate.query.count() + BulkUpdateLog.query.count()

    # Render partial table rows
    recent_updates_html = render_template("partials/recent_updates_rows.html", recent_updates=recent_updates)

    return jsonify({
        "status": "success",
        "recent_updates_html": recent_updates_html,
        "total_callerid_updates": total_callerid_updates
    })
@main_bp.route('/ajax_refresh_allowed_users')
def ajax_refresh_allowed_users():
    # Fetch allowed users from DB
    allowed_users = AllowedUser.query.all()

    # Compute online/offline counts
    online_count = sum(1 for u in allowed_users if u.is_online)
    offline_count = len(allowed_users) - online_count

    # Render partial HTML for the allowed users list
    allowed_users_html = render_template(
        'partials/allowed_users_list.html', 
        allowed_users=allowed_users,
        online_count=online_count,
        offline_count=offline_count
    )

    return jsonify({
        "status": "success",
        "allowed_users_html": allowed_users_html,
        "online_count": online_count,
        "offline_count": offline_count
    })
# ---------------- Generic AJAX table endpoint ----------------
@main_bp.route("/ajax/<table_type>")
@login_required
def ajax_table(table_type):
    return render_table(table_type)

# ---------------- Allowed user management (AJAX) ----------------
@main_bp.route("/ajax/add_allowed_user", methods=["POST"])
@login_required
@admin_required
def ajax_add_allowed_user():
    try:
        # Try JSON first, fallback to form data
        data = request.get_json(silent=True) or request.form.to_dict()

        email = (data.get("email") or "").strip().lower()
        password = (data.get("password") or "").strip() or "DefaultPass123!"

        if not email:
            return jsonify({"status": "error", "message": "Email required."}), 400

        if AllowedUser.query.filter(func.lower(AllowedUser.email) == email).first():
            return jsonify({"status": "error", "message": "User already exists."}), 400

        user = AllowedUser(email=email, password=password, default_password=password)
        db.session.add(user)
        db.session.commit()

        log_activity(
            "ADD_ALLOWED_USER",
            user_email=session.get("user_email"),
            details=f"Added allowed user {email}"
        )

        table_html = render_table("allowed")
        return jsonify({"status": "success", "table_html": table_html})

    except Exception as e:
        current_app.logger.exception("ajax_add_allowed_user error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500


@main_bp.route("/ajax/edit_allowed_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def ajax_edit_allowed_user(user_id):
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        password = (data.get("password") or "").strip()
        user = AllowedUser.query.get_or_404(user_id)
        old_email = user.email
        if email:
            user.email = email
        if password:
            user.password = password
            user.default_password = password
        db.session.commit()
        log_activity("EDIT_ALLOWED_USER", user_email=session.get("user_email"), details=f"Edited allowed user {old_email} -> {user.email}")
        return jsonify({"status": "success", "table_html": render_table("allowed")})
    except Exception as e:
        current_app.logger.exception("ajax_edit_allowed_user error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

@main_bp.route("/ajax/delete_allowed_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def ajax_delete_allowed_user(user_id):
    try:
        user = AllowedUser.query.get_or_404(user_id)
        email = user.email
        db.session.delete(user)
        db.session.commit()
        log_activity("DELETE_ALLOWED_USER", user_email=session.get("user_email"), details=f"Deleted allowed user {email}")
        return jsonify({"status": "success", "table_html": render_table("allowed")})
    except Exception as e:
        current_app.logger.exception("ajax_delete_allowed_user error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

# ---------------- Admin user management (AJAX) ----------------
@main_bp.route("/ajax/add_admin", methods=["POST"])
@login_required
@admin_required
def ajax_add_admin():
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        password = (data.get("password") or "").strip() or "DefaultPass123!"
        if not email:
            return jsonify({"status": "error", "message": "Email required."}), 400
        if Admin.query.filter(func.lower(Admin.email) == email).first():
            return jsonify({"status": "error", "message": "Admin already exists."}), 400
        admin = Admin(email=email, password=password, default_password=password)
        db.session.add(admin)
        db.session.commit()
        log_activity("ADD_ADMIN", user_email=session.get("user_email"), details=f"Added admin {email}")
        return jsonify({"status": "success", "table_html": render_table("admins")})
    except Exception as e:
        current_app.logger.exception("ajax_add_admin error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

@main_bp.route("/ajax/edit_admin/<int:admin_id>", methods=["POST"])
@login_required
@admin_required
def ajax_edit_admin(admin_id):
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        password = (data.get("password") or "").strip()
        admin = Admin.query.get_or_404(admin_id)
        old_email = admin.email
        if email:
            admin.email = email
        if password:
            admin.password = password
            admin.default_password = password
        db.session.commit()
        log_activity("EDIT_ADMIN", user_email=session.get("user_email"), details=f"Edited admin {old_email} -> {admin.email}")
        return jsonify({"status": "success", "table_html": render_table("admins")})
    except Exception as e:
        current_app.logger.exception("ajax_edit_admin error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

@main_bp.route("/ajax/delete_admin/<int:admin_id>", methods=["POST"])
@login_required
@admin_required
def ajax_delete_admin(admin_id):
    try:
        admin = Admin.query.get_or_404(admin_id)
        current_user = (session.get("user_email") or "").strip().lower()
        if current_user == admin.email.strip().lower():
            return jsonify({"status": "error", "message": "Cannot delete yourself."}), 400
        email = admin.email
        db.session.delete(admin)
        db.session.commit()
        log_activity("DELETE_ADMIN", user_email=session.get("user_email"), details=f"Deleted admin {email}")
        return jsonify({"status": "success", "table_html": render_table("admins")})
    except Exception as e:
        current_app.logger.exception("ajax_delete_admin error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

# ---------------- Single-User Caller ID Update (AJAX) ----------------
@main_bp.route("/ajax/update_callerid", methods=["POST"])
@login_required
def ajax_update_callerid():
    try:
        payload = request.get_json()
        email = (payload.get("email") or "").strip().lower()
        caller_id = (payload.get("caller_id") or "").strip()
        if not email or not caller_id:
            return jsonify({"status": "error", "message": "Email and Caller ID required."}), 400

        res = safe_update_line_key(email, caller_id)
        now = datetime.utcnow()
        rec = CallerIDUpdate(
            user_id=email,
            extension=res.get("extension") or "N/A",
            caller_id_name=email.split("@")[0],
            caller_id_number=caller_id,
            status="Success" if res.get("success") else "Failed",
            updated_by=session.get("user_email"),
            updated_ts=now
        )
        db.session.add(rec)
        db.session.add(BulkUpdateLog(email=email, old_caller_id=None, new_caller_id=caller_id, timestamp=now))
        db.session.commit()

        log_activity("SINGLE_UPDATE", action=f"{email} -> {caller_id}")

        return jsonify({
            "status": "success" if res.get("success") else "error",
            "message": "Updated successfully" if res.get("success") else f"Failed: {res.get('reason')}",
            "updated_by": rec.updated_by,
            "updated_ts": rec.updated_ts.isoformat()
        })
    except Exception as e:
        logger.exception("ajax_update_callerid error: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500
    
@main_bp.route("/ajax_refresh_callerid")
@login_required
def ajax_refresh_callerid():
    updates = CallerIDUpdate.query.order_by(CallerIDUpdate.updated_ts.desc()).limit(1000).all()
    uploaded_data = [
        {
            "email": u.user_id,
            "outbound_caller_id": u.caller_id_number,
            "status": u.status,
            "reason": u.reason,
            "updated_by": u.updated_by,
            "updated_ts": u.updated_ts.strftime("%Y-%m-%d %H:%M:%S") if u.updated_ts else "-"
        } for u in updates
    ]
    html = render_template("partials/callerid_updates_table.html", uploaded_data=uploaded_data)
    return jsonify({"status": "success", "html": html})

# ---------------- Inline Single-User Update via ⚙ ----------------
@main_bp.route("/ajax/update_callerid_inline", methods=["POST"])
@login_required
def ajax_update_callerid_inline():
    try:
        data = request.json
        user_email = data.get("email")
        new_callerid = data.get("caller_id")

        # Update in DB (CallerIDUpdate table)
        update_record = CallerIDUpdate(
            user_id=user_email,
            caller_id_number=new_callerid,
            caller_id_name=user_email.split("@")[0],
            extension="N/A",  # or fetch from Zoom if needed
            status="Success",  # or "Pending" if you call Zoom API
            updated_by=session.get("user_email"),
            updated_ts=datetime.utcnow()
        )

        
        db.session.add(update_record)
        db.session.commit()

        logger.info("Updated caller ID for %s to %s", user_email, new_callerid)

        # Fetch updated list to display
        updates = CallerIDUpdate.query.order_by(CallerIDUpdate.updated_ts.desc()).all()
        return jsonify({
            "status": "success",
            "updates": [
                {
                    "email": u.user_id,
                    "caller_id": u.caller_id_number,
                    "updated_by": u.updated_by,
                    "timestamp": u.updated_ts.strftime("%Y-%m-%d %H:%M:%S")
                } for u in updates
            ]
        })
    except Exception as e:
        logger.exception("Error updating caller ID: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500

# ---------------- Row-level single-update endpoint used by bulk-page per-row Update buttons ----------------
@main_bp.route("/ajax/update_row", methods=["POST"])
@login_required
def ajax_update_row():
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        caller_id = str(data.get("caller_id") or "").strip()
        if not email or not caller_id:
            return jsonify({"status": "error", "message": "Email and caller_id required."}), 400

        zoom_res = safe_update_line_key(email, caller_id)
        extension = zoom_res.get("extension") or "N/A"

        now = datetime.utcnow()
        rec = CallerIDUpdate(
            user_id=email,
            extension=extension,
            caller_id_name=email.split("@")[0],
            caller_id_number=caller_id,
            status="Success" if zoom_res.get("success") else "Failed",
            updated_by=session.get("user_email"),
            updated_ts=now
        )
        db.session.add(rec)
        db.session.add(BulkUpdateLog(email=email, old_caller_id=None, new_caller_id=caller_id, timestamp=now))
        db.session.commit()

        log_activity("ROW_UPDATE", user_email=session.get("user_email"), details=f"Row update {email} -> {caller_id}")

        return jsonify({
            "status": "success" if zoom_res.get("success") else "error",
            "message": "Updated" if zoom_res.get("success") else f"Failed: {zoom_res.get('reason')}",
            "updated_by": rec.updated_by,
            "updated_ts": rec.updated_ts.isoformat()
        })
    except Exception as e:
        current_app.logger.exception("ajax_update_row error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

# ---------------- Bulk Update / File Upload ----------------
MAX_UPLOAD_SIZE_MB = 10

@main_bp.route("/ajax/bulk_update_file", methods=["POST"])
@login_required
def ajax_bulk_update_file():
    try:
        cleanup_bulk_session()
        f = request.files.get("file")
        if not f:
            return jsonify({"status": "error", "message": "No file uploaded."}), 400
        if not f.filename.endswith((".xlsx", ".xls")):
            return jsonify({"status": "error", "message": "File must be .xlsx or .xls."}), 400

        f.seek(0, os.SEEK_END)
        size_mb = f.tell() / (1024 * 1024)
        f.seek(0)
        if size_mb > MAX_UPLOAD_SIZE_MB:
            return jsonify({"status": "error", "message": f"File too large: {size_mb:.2f} MB. Max {MAX_UPLOAD_SIZE_MB} MB."}), 400

        df = pd.read_excel(f)
        if "email" not in df.columns or "outbound_caller_id" not in df.columns:
            return jsonify({"status": "error", "message": "Excel must contain 'email' and 'outbound_caller_id' columns."}), 400

        df = df[["email", "outbound_caller_id"]]
        bulk_list = df.to_dict(orient="records")
        session[SESSION_BULK_KEY] = bulk_list
        session[SESSION_LAST_UPDATE_TS] = datetime.utcnow().isoformat()
        session[SESSION_BULK_DOWNLOADED] = False
        session.modified = True

        log_activity("UPLOAD_BULK_FILE", user_email=session.get("user_email"), details=f"Uploaded bulk file with {len(bulk_list)} rows")

        table_html = render_table("bulk")
        return jsonify({"status": "success", "updated_table_html": table_html, "count": len(bulk_list)})
    except Exception as e:
        current_app.logger.exception("ajax_bulk_update_file error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

# ---------------- Apply Bulk Update ----------------
@main_bp.route("/ajax/apply_bulk_update", methods=["POST"])
@login_required
def ajax_apply_bulk_update():
    try:
        bulk_data = session.get(SESSION_BULK_KEY, [])
        if not bulk_data:
            return jsonify({"status": "error", "message": "No bulk data uploaded."}), 400

        data = request.get_json(force=True)
        selected_emails = [e.strip().lower() for e in data.get("selected_users", [])]
        filtered_rows = [r for r in bulk_data if (r.get("email") or "").strip().lower() in selected_emails]

        results = []
        bulk_start = datetime.utcnow()

        for row in filtered_rows:
            email = (row.get("email") or "").strip()
            cid = str(row.get("outbound_caller_id") or "")
            now = datetime.utcnow()

            if not email or not cid:
                # Skip or mark as failed if missing data
                results.append({"email": email, "caller_id": cid, "success": False, "reason": "Missing email or caller ID", "extension": "N/A"})
                log_activity(
                    "BULK_UPDATE_ERROR",
                    user_email=session.get("user_email"),
                    action=f"Failed to update {email}: Missing email or caller ID",
                    session_duration=0
                )
                continue

            # Safe update to Zoom API
            zoom_res = safe_update_line_key(email, cid)
            success = zoom_res.get("success", False)
            reason = zoom_res.get("reason", "Unknown error")
            extension = zoom_res.get("extension") or "N/A"

            # Record in DB
            u = CallerIDUpdate(
                user_id=email,
                extension=extension,
                caller_id_name=email.split("@")[0],
                caller_id_number=cid,
                status="Success" if success else "Failed",
                updated_by=session.get("user_email"),
                updated_ts=now
            )
            db.session.add(u)
            db.session.add(BulkUpdateLog(email=email, old_caller_id=None, new_caller_id=cid, timestamp=now))

            # Log per row
            if success:
                log_activity(
                    "BULK_UPDATE",
                    user_email=session.get("user_email"),
                    action=f"Successfully updated {email} → {cid}",
                    session_duration=0
                )
            else:
                log_activity(
                    "BULK_UPDATE_ERROR",
                    user_email=session.get("user_email"),
                    action=f"Failed to update {email}: {reason}",
                    session_duration=0
                )

            results.append({
                "email": email,
                "caller_id": cid,
                "success": success,
                "reason": reason,
                "extension": extension
            })

        db.session.commit()
        bulk_end = datetime.utcnow()
        duration = (bulk_end - bulk_start).total_seconds()

        log_activity(
            "BULK_UPDATE",
            user_email=session.get("user_email"),
            action=f"Bulk update applied for {len(filtered_rows)} users",
            session_duration=duration
        )

        return jsonify({
            "status": "success",
            "message": f"Applied updates: {sum(1 for r in results if r['success'])}/{len(results)} succeeded",
            "results": results
        })

    except Exception as e:
        current_app.logger.exception("ajax_apply_bulk_update error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

# ---------------- Download Updated Template ----------------
@main_bp.route("/ajax/download_updated_template", methods=["POST"])
@login_required
def ajax_download_updated_template():
    try:
        if is_bulk_session_stale():
            cleanup_bulk_session()
            return jsonify({"status": "error", "message": "Bulk session expired. Please re-upload file."}), 400

        bulk_data = session.get(SESSION_BULK_KEY, [])
        if not bulk_data:
            return jsonify({"status": "error", "message": "No bulk data available to download."}), 400

        if session.get(SESSION_BULK_DOWNLOADED, False):
            return jsonify({"status": "error", "message": "This bulk data has already been downloaded."}), 400

        data = request.get_json(force=True) or {}
        selected = data.get("selected_emails", [])
        if selected:
            selected_norm = [s.strip().lower() for s in selected]
            export_rows = [r for r in bulk_data if (r.get("email") or "").strip().lower() in selected_norm]
            if not export_rows:
                return jsonify({"status": "error", "message": "No matching users selected for download."}), 400
        else:
            export_rows = bulk_data

        MAX_DOWNLOAD_ROWS = 1000
        if len(export_rows) > MAX_DOWNLOAD_ROWS:
            return jsonify({"status": "error", "message": f"Download limit exceeded: {len(export_rows)} rows (max {MAX_DOWNLOAD_ROWS})."}), 400

        df = pd.DataFrame(export_rows)
        statuses = {}
        for row in export_rows:
            e = (row.get("email") or "").strip().lower()
            latest = CallerIDUpdate.query.filter(func.lower(CallerIDUpdate.user_id) == e)\
                                         .order_by(CallerIDUpdate.updated_ts.desc()).first()
            statuses[e] = {
                "status": latest.status if latest else "",
                "extension": latest.extension if latest else "",
                "updated_by": latest.updated_by if latest else "",
                "timestamp": latest.updated_ts.isoformat() if latest else ""
            }

        df["status"] = df["email"].apply(lambda x: statuses.get((x or "").strip().lower(), {}).get("status", ""))
        df["extension"] = df["email"].apply(lambda x: statuses.get((x or "").strip().lower(), {}).get("extension", ""))
        df["updated_by"] = df["email"].apply(lambda x: statuses.get((x or "").strip().lower(), {}).get("updated_by", ""))
        df["timestamp"] = df["email"].apply(lambda x: statuses.get((x or "").strip().lower(), {}).get("timestamp", ""))

        output = io.BytesIO()
        df.to_excel(output, index=False)
        output.seek(0)

        session[SESSION_BULK_DOWNLOADED] = True
        session.modified = True

        log_activity("DOWNLOAD_BULK", user_email=session.get("user_email"), details=f"Downloaded {len(export_rows)} rows")

        cleanup_bulk_session()

        return send_file(
            output,
            as_attachment=True,
            download_name="bulk_updated_template.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    except Exception as e:
        current_app.logger.exception("ajax_download_updated_template error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

# ---------------- Logout Route (logs logout & duration) ----------------
@main_bp.route("/logout")
@login_required
def logout():
    try:
        user_email = session.get("user_email")
        login_ts = session.get("login_ts")
        duration = None
        if login_ts:
            try:
                if isinstance(login_ts, str):
                    dt = datetime.fromisoformat(login_ts)
                else:
                    dt = login_ts
                duration = (datetime.utcnow() - dt).total_seconds()
            except Exception:
                duration = None

        log_activity("LOGOUT", user_email=user_email, details="User logged out", duration_seconds=duration)

        # clear session
        session_keys = list(session.keys())
        for k in session_keys:
            session.pop(k, None)

        flash("You have been logged out.", "info")
        return redirect(url_for("auth.login"))
    except Exception as e:
        current_app.logger.exception("logout error: %s", e)
        session.clear()
        flash("Logged out (with errors).", "warning")
        return redirect(url_for("auth.login"))

# ---------------- Non-AJAX Admin management helpers (legacy forms) - kept for compatibility ----------------
@main_bp.route("/delete_admin/<int:admin_id>", methods=["POST"])
@admin_required
@login_required
def delete_admin(admin_id):
    try:
        admin = Admin.query.get_or_404(admin_id)
        current_user_email = (session.get("user_email") or "").strip().lower()
        if current_user_email == admin.email.strip().lower():
            flash("❌ Cannot delete yourself.", "danger")
            return redirect(url_for("main.manage_admins_access"))

        db.session.delete(admin)
        db.session.commit()
        log_activity("DELETE_ADMIN", user_email=session.get("user_email"), details=f"Deleted admin {admin.email}")
        flash("✅ Admin removed.", "success")
    except Exception as e:
        current_app.logger.error("delete_admin error: %s\n%s", e, traceback.format_exc())
        flash(f"Server error: {e}", "danger")
    return redirect(url_for("main.manage_admins_access"))

@main_bp.route("/delete_access_user/<int:user_id>", methods=["POST"])
@admin_required
@login_required
def delete_access_user(user_id):
    try:
        user = AllowedUser.query.get_or_404(user_id)
        email = user.email
        db.session.delete(user)
        db.session.commit()
        log_activity("DELETE_ALLOWED_USER", user_email=session.get("user_email"), details=f"Deleted allowed user {email}")
        flash("✅ Allowed user removed.", "success")
    except Exception as e:
        current_app.logger.error("delete_access_user error: %s\n%s", e, traceback.format_exc())
        flash(f"Server error: {e}", "danger")
    return redirect(url_for("main.manage_admins_access"))

@main_bp.route("/manage_admins_access", methods=["GET", "POST"])
@admin_required
@login_required
def manage_admins_access():
    admins = Admin.query.order_by(Admin.created_at.desc()).all()
    access_users = AllowedUser.query.order_by(AllowedUser.created_at.desc()).all()
    if request.method == "POST":
        action = request.form.get("action")
        email = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip() or "DefaultPass123!"
        if not email:
            flash("❌ Email is required.", "danger")
            return redirect(url_for("main.manage_admins_access"))

        try:
            if action == "add_admin":
                if not Admin.query.filter(func.lower(Admin.email) == email).first():
                    admin = Admin(email=email, password=password, default_password=password)
                    db.session.add(admin)
                    db.session.commit()
                    log_activity("ADD_ADMIN", user_email=session.get("user_email"), details=f"Added admin {email}")
                    flash(f"✅ {email} added as Admin.", "success")
                else:
                    flash(f"⚠️ {email} is already an Admin.", "warning")
            elif action == "add_access_user":
                if not AllowedUser.query.filter(func.lower(AllowedUser.email) == email).first():
                    user = AllowedUser(email=email, password=password, default_password=password)
                    db.session.add(user)
                    db.session.commit()
                    log_activity("ADD_ALLOWED_USER", user_email=session.get("user_email"), details=f"Added allowed user {email}")
                    flash(f"✅ {email} added to allowed users.", "success")
                else:
                    flash(f"⚠️ {email} is already an allowed user.", "warning")
        except Exception as e:
            current_app.logger.exception("manage_admins_access POST error: %s", e)
            flash(f"Server error: {e}", "danger")
        return redirect(url_for("main.manage_admins_access"))

    return render_template("manage_admins_access.html", admins=admins, access_users=access_users)

@main_bp.route("/ajax/reset_password/<string:user_type>/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def ajax_reset_password(user_type, user_id):
    try:
        new_password = "DefaultPass123!"
        if user_type == "allowed":
            user = AllowedUser.query.get_or_404(user_id)
        elif user_type == "admin":
            user = Admin.query.get_or_404(user_id)
        else:
            return jsonify({"status": "error", "message": "Invalid user type."}), 400

        old_email = user.email
        user.password = new_password
        user.default_password = new_password
        db.session.commit()

        log_activity("RESET_PASSWORD", user_email=session.get("user_email"),
                     details=f"Reset password for {user_type} {old_email}")

        return jsonify({"status": "success", "message": f"Password reset to default for {old_email}",
                        "new_password": new_password,
                        "table_html": render_table(user_type if user_type == "allowed" else "admins")})
    except Exception as e:
        current_app.logger.exception("ajax_reset_password error: %s", e)
        return jsonify({"status": "error", "message": f"Server error: {e}"}), 500

# ---------------- End of File ----------------











