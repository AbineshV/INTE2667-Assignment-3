from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

# Database: SQLAlchemy ORM
db = SQLAlchemy()

# Authentication: Flask-Login manages logged-in user sessions
login_manager = LoginManager()
login_manager.login_view = "auth.login"

# CSRF protection for forms and state-changing requests
csrf = CSRFProtect()
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# R16: rate limiting — keyed by client IP address
limiter = Limiter(key_func=get_remote_address)
