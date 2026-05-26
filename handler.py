import os
import sys
import tempfile


PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

if os.environ.get("VERCEL"):
    os.chdir(tempfile.gettempdir())

from app import app

app.template_folder = os.path.join(PROJECT_DIR, "templates")
