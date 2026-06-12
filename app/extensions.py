"""Flask extensions instantiated outside the app factory so they can be imported
without circular dependencies. Each extension is initialised in create_app()."""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()
