#settings.py
import logging
import logging.config
import os
from logging.handlers import RotatingFileHandler

# --- Directory and File Setup ---

# Ensure logs directory exists relative to the settings.py file
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# Define the log file path
LOG_FILE = os.path.join(LOG_DIR, 'app.log')

# --- Logging Configuration Dictionary ---

LOGGING = {
    'version': 1,
    # Disable default loggers that might be configured elsewhere
    'disable_existing_loggers': False,
    'formatters': {
        # Define a detailed format for all logs
        'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s.%(funcName)s: %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
    },
    'handlers': {
        # Handler for console output
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'default',
        },
        # Handler for file output with rotation
        'file': {
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': LOG_FILE,
            'formatter': 'default',
            'mode': 'a',
            'encoding': 'utf-8',
            'maxBytes': 5 * 1024 * 1024,  # 5 MB per file
            'backupCount': 5,             # Keep the last 5 logs
        },
    },
    # Root logger configuration: captures everything
    'root': {
        'level': os.environ.get('LOG_LEVEL', 'INFO'), # Default to INFO level
        'handlers': ['console', 'file'],
    },
}

# Apply the configuration
logging.config.dictConfig(LOGGING)

# Create a global logger instance for easy import in other modules
logger = logging.getLogger('📞 Zoom Caller ID Manage')

# Convenience variable for the log file path (optional, but helpful)
LOG_FILE_PATH = LOG_FILE


