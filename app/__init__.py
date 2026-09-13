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
    if not _SECRET_KEY_FILE.exists():
        # Write to a temp file, then hard-link it into place: the link fails if
        # another worker got there first, so every worker ends up reading the same key
        tmp = _SECRET_KEY_FILE.with_name(f".secret_key.{os.getpid()}")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
            os.link(tmp, _SECRET_KEY_FILE)
        except FileExistsError:
            pass
        finally:
            tmp.unlink(missing_ok=True)
    return _SECRET_KEY_FILE.read_text().strip()


def create_app():
    app = Flask(__name__)
    app.secret_key = _get_or_create_secret_key()

    from app.routes import main
    app.register_blueprint(main)

    return app
