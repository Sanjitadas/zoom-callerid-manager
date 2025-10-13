#settings.py
import logging
import logging.config
import os

# Ensure logs directory exists
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, 'app.log')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'default': {
            'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'default',
        },
        'file': {
            'class': 'logging.FileHandler',
            'filename': LOG_FILE,
            'formatter': 'default',
            'mode': 'a',  # append mode
            'encoding': 'utf-8',
        },
    },
    'root': {
        'level': 'INFO',
        'handlers': ['console', 'file'],
    },
}

# Apply logging configuration
logging.config.dictConfig(LOGGING)

# Global logger to import anywhere
logger = logging.getLogger(__name__)

