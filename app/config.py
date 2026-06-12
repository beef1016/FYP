"""Per-environment Flask config classes (FYP spec section 18: Factory pattern)."""
import os

# Project root (the directory containing the `app/` package and `run.py`)
_BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
_INSTANCE_DIR = os.path.join(_BASE_DIR, "instance")


class BaseConfig:
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    INSTANCE_DIR = _INSTANCE_DIR


class DevConfig(BaseConfig):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(_INSTANCE_DIR, "scans.db")


class TestConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


class ProdConfig(BaseConfig):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(_INSTANCE_DIR, "scans.db")


CONFIG_BY_NAME = {
    "dev": DevConfig,
    "test": TestConfig,
    "prod": ProdConfig,
}
