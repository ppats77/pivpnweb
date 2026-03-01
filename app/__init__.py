import os
import secrets
from pathlib import Path

from flask import Flask

_SECRET_KEY_FILE = Path(__file__).parent.parent / ".secret_key"


def _get_or_create_secret_key() -> str:
    """Return a stable secret key, persisted to disk if not set via env."""
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    # Persist a generated key so it survives restarts and is shared across workers
    try:
        return _SECRET_KEY_FILE.read_text().strip()
    except FileNotFoundError:
        key = secrets.token_hex(32)
        _SECRET_KEY_FILE.write_text(key)
        _SECRET_KEY_FILE.chmod(0o600)
        return key


def create_app():
    app = Flask(__name__)
    app.secret_key = _get_or_create_secret_key()

    from app.routes import main
    app.register_blueprint(main)

    return app
