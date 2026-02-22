"""
Flask Application Configuration
"""
import os
import tempfile

basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-prod')

    # Database — SQLite stored alongside the app
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(basedir, 'malstat.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Upload limits
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB
    UPLOAD_FOLDER = tempfile.gettempdir()

    # In-memory job store (async polling only — DB is for persistence)
    JOBS = {}
