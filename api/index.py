import os
import sys

# Add root directory to sys.path so app, database, etc. can be imported
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app as flask_app
from database.db import init_db

# Ensure SQLite DB is initialized in Vercel /tmp directory
try:
    init_db()
except Exception:
    pass

class VercelPathFixMiddleware:
    """
    WSGI Middleware to clean up Vercel path rewrites.
    Strips internal '/api/index' prefix if Vercel prepends it to PATH_INFO.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path.startswith("/api/index"):
            new_path = path[len("/api/index"):] or "/"
            environ["PATH_INFO"] = new_path
        elif path in ["/api", "/api/"]:
            environ["PATH_INFO"] = "/"
        return self.wsgi_app(environ, start_response)

flask_app.wsgi_app = VercelPathFixMiddleware(flask_app.wsgi_app)
app = flask_app
