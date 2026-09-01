import os
import sys

# Add root directory to sys.path so app, database, etc. can be imported
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app import app

# Expose WSGI application for Vercel Serverless Function runtime
app = app
