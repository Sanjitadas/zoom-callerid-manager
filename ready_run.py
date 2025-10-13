# ready_run.py
from app import create_app
from extensions import db
from models import Admin

app = create_app()

with app.app_context():
    db.create_all()
    print("✅ Database initialized successfully.")

    # Default admins
    default_admins = [
        {"email": "Sanjita.Das@blackbox.com", "password": "Admin123!"},
        {"email": "Rajeev.Gupta@blackbox.com", "password": "Admin123!"}
    ]

    for adm in default_admins:
        email_lower = adm["email"].strip().lower()
        existing = Admin.query.filter_by(email=email_lower).first()
        if not existing:
            admin = Admin(email=email_lower, password=adm["password"])
            db.session.add(admin)
            print(f"Added admin: {email_lower}")
        else:
            # Update password if exists
            existing.password = adm["password"]
            print(f"Updated password for admin: {email_lower}")
    db.session.commit()
    print("✅ Default admins added/updated successfully.")





















