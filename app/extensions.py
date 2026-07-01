"""Flask extensions instantiated outside the app factory so they can be imported
without circular dependencies. Each extension is initialised in create_app()."""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_httpauth import HTTPBasicAuth
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
migrate = Migrate()

# Single-user HTTP Basic Auth. Verify callback is wired in create_app().
auth = HTTPBasicAuth()

# Per-source-IP rate limiter. Default + per-route limits set via config and
# decorators on the routes themselves.
limiter = Limiter(key_func=get_remote_address)
