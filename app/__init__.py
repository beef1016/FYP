"""
Flask application factory.

Wires together the SQLAlchemy extension, all services (DatabaseManager,
ExploitCorrelator, ReportGenerator, OrchestrationEngine, SearchsploitAdapter)
and registers the controller Blueprints. Implements the Factory Pattern called
out in section 18 of the FYP specification.
"""
import os
from flask import Flask

from .extensions import db, migrate
from .config import DevConfig


def create_app(config_class=DevConfig):
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(app.config["INSTANCE_DIR"], exist_ok=True)

    # Register models against db.metadata BEFORE init_app so Flask-Migrate sees them
    from . import models  # noqa: F401

    db.init_app(app)
    migrate.init_app(app, db)

    # --- Wire services ----------------------------------------------------
    from .services.db_manager import DatabaseManager
    from .services.exploit_correlator import ExploitCorrelator
    from .services.report_generator import ReportGenerator
    from .engine.searchsploit_adapter import SearchsploitAdapter
    from .engine.orchestration import OrchestrationEngine

    db_manager = DatabaseManager(db)
    searchsploit = SearchsploitAdapter()
    correlator = ExploitCorrelator(searchsploit, db_manager)
    report_gen = ReportGenerator()
    orchestrator = OrchestrationEngine(app, db_manager, correlator)

    # --- Register controllers --------------------------------------------
    from .controllers.pages_controller import PagesController
    from .controllers.scan_controller import ScanController
    from .controllers.tool_controller import ToolController
    from .controllers.report_controller import ReportController

    PagesController(db_manager).register(app)
    ScanController(orchestrator, db_manager).register(app)
    ToolController().register(app)
    ReportController(db_manager, report_gen).register(app)

    return app
