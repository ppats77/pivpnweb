import subprocess
from functools import wraps

from flask import redirect, session, url_for

from app.services.pivpn import get_setup_vars


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("main.login"))
        return f(*args, **kwargs)
    return decorated


def authenticate(username: str, password: str) -> bool:
    """Authenticate against the system user that installed PiVPN."""
    setup = get_setup_vars()
    if not setup:
        return False

    pivpn_user = setup.get("install_user", "")
    if username != pivpn_user:
        return False

    try:
        proc = subprocess.run(
            ["su", "-c", "echo", username],
            input=password + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False
