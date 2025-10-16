# app.py
# app.py
from flask import Flask, render_template
from flask_migrate import Migrate
from datetime import datetime
from extensions import db, bcrypt, mail, login_manager
from models import Admin, AllowedUser
import logging.config
from settings import LOGGING  # centralized logging config

from auth import auth_bp
from routes import main_bp
# 🚨 FIX: Import the helper functions used in templates
from routes import render_unified_report, render_table 


def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    Migrate(app, db)

    # Setup centralized logging
    logging.config.dictConfig(LOGGING)
    app.logger = logging.getLogger('📞 Zoom Caller ID Manage')

    # Context processor for templates
    @app.context_processor
    def inject_now():
        return {"now": datetime.now, "current_year": datetime.now().year}
    
    # 🔑 FIX: Register helper functions as Jinja globals
    # These functions can now be called directly in any template: {{ render_unified_report() }}
    app.jinja_env.globals.update(
        render_unified_report=render_unified_report,
        render_table=render_table
    )

    # Flask-Login user loader
    @login_manager.user_loader
    def load_user(user_id):
        user = Admin.query.get(int(user_id))
        if not user:
            user = AllowedUser.query.get(int(user_id))
        return user
    
    @app.errorhandler(404)
    def not_found(e):
      return render_template("404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
      return render_template("500.html"), 500

    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)  # no prefix, '/' will now work

    return app























































