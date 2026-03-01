import subprocess
from functools import wraps

from flask import redirect, session, url_for

from app.services.pivpn import DEV_MODE, get_setup_vars


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

    # In dev mode, accept any password for the pivpn user
    if DEV_MODE:
        return True

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


def change_password(username: str, new_password: str) -> tuple[bool, str]:
    """Change the system password for the given user via chpasswd."""
    if DEV_MODE:
        return True, "Password changed (dev mode)"

    try:
        proc = subprocess.run(
            ["sudo", "chpasswd"],
            input=f"{username}:{new_password}",
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            return True, "Password changed successfully"
        return False, proc.stderr.strip() or "Failed to change password"
    except subprocess.TimeoutExpired:
        return False, "Password change timed out"
    except OSError as e:
        return False, str(e)
