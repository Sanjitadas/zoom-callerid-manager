# create_user.py
from app import db
from models import AllowedUser
from werkzeug.security import generate_password_hash

# Replace with your actual org email and password
user = AllowedUser(
    email="First.Last@Blackbox.com",
    password_hash=generate_password_hash("YourPassword")
)

db.session.add(user)
db.session.commit()
print("✅ User added successfully!")
