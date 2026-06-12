"""Application entry point.

The Flask app instance is built by the factory in `app/__init__.py`. Running
this file (or pointing `flask run` at it) starts the dev server.
"""
from app import create_app

app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
