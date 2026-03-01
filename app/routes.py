import io
import re

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from app.auth import authenticate, change_password, login_required
from app.services.pivpn import (
    create_client,
    detect_vpn_protocol,
    disable_client,
    enable_client,
    get_client_config,
    get_vpn_version,
    list_clients,
    revoke_client,
)

main = Blueprint("main", __name__)

_SAFE_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9._@-]*$")


def _validate_client_name(name: str) -> bool:
    return bool(_SAFE_NAME_RE.match(name))


@main.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("main.dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("user", "")
        password = request.form.get("password", "")
        if authenticate(username, password):
            session["authenticated"] = True
            session["username"] = username
            return redirect(url_for("main.dashboard"))
        error = "Username or Password wrong"

    vpn_version = get_vpn_version()
    return render_template("login.html", error=error, vpn_version=vpn_version)


@main.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("main.login"))


@main.route("/change-password", methods=["POST"])
@login_required
def password_change():
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")
    username = session.get("username", "")

    if not current_pw or not new_pw or not confirm_pw:
        flash("All fields are required", "error")
        return redirect(url_for("main.dashboard"))

    if new_pw != confirm_pw:
        flash("New passwords do not match", "error")
        return redirect(url_for("main.dashboard"))

    if len(new_pw) < 6:
        flash("New password must be at least 6 characters", "error")
        return redirect(url_for("main.dashboard"))

    if not authenticate(username, current_pw):
        flash("Current password is incorrect", "error")
        return redirect(url_for("main.dashboard"))

    success, msg = change_password(username, new_pw)
    if success:
        flash("Password changed successfully", "success")
    else:
        flash(f"Failed to change password: {msg}", "error")

    return redirect(url_for("main.dashboard"))


@main.route("/")
@login_required
def dashboard():
    protocol = detect_vpn_protocol()
    vpn_version = get_vpn_version()
    clients = list_clients()

    active_clients = [c for c in clients if c.status == "valid"]
    expired_clients = [c for c in clients if c.status == "expired"]

    return render_template(
        "dashboard.html",
        protocol=protocol,
        vpn_version=vpn_version,
        active_clients=active_clients,
        expired_clients=expired_clients,
    )


@main.route("/clients/new", methods=["POST"])
@login_required
def new_client():
    name = request.form.get("name", "").strip()
    days = request.form.get("days", "1080")
    password = request.form.get("password", "")

    if not name:
        flash("Client name is required", "error")
        return redirect(url_for("main.dashboard"))

    if not _validate_client_name(name):
        flash("Invalid client name. Must start with a letter; only alphanumeric and .-@_ allowed.", "error")
        return redirect(url_for("main.dashboard"))

    try:
        days_int = int(days)
        if days_int < 1 or days_int > 3650:
            days_int = 1080
    except ValueError:
        days_int = 1080

    success, output = create_client(name, days_int, password)
    if success:
        flash(f"Client '{name}' created successfully", "success")
    else:
        flash(f"Error creating client: {output}", "error")

    return redirect(url_for("main.dashboard"))


@main.route("/clients/<name>/enable", methods=["POST"])
@login_required
def enable(name: str):
    if not _validate_client_name(name):
        flash("Invalid client name", "error")
        return redirect(url_for("main.dashboard"))
    protocol = request.form.get("protocol", "")
    success, output = enable_client(name, protocol)
    if not success:
        flash(f"Error enabling client: {output}", "error")
    return redirect(url_for("main.dashboard"))


@main.route("/clients/<name>/disable", methods=["POST"])
@login_required
def disable(name: str):
    if not _validate_client_name(name):
        flash("Invalid client name", "error")
        return redirect(url_for("main.dashboard"))
    protocol = request.form.get("protocol", "")
    success, output = disable_client(name, protocol)
    if not success:
        flash(f"Error disabling client: {output}", "error")
    return redirect(url_for("main.dashboard"))


@main.route("/clients/<name>/revoke", methods=["POST"])
@login_required
def revoke(name: str):
    if not _validate_client_name(name):
        flash("Invalid client name", "error")
        return redirect(url_for("main.dashboard"))
    protocol = request.form.get("protocol", "")
    success, output = revoke_client(name, protocol)
    if success:
        flash(f"Client '{name}' revoked", "success")
    else:
        flash(f"Error revoking client: {output}", "error")
    return redirect(url_for("main.dashboard"))


@main.route("/clients/<name>/download")
@login_required
def download(name: str):
    if not _validate_client_name(name):
        flash("Invalid client name", "error")
        return redirect(url_for("main.dashboard"))
    protocol = request.args.get("protocol", "")
    config = get_client_config(name, protocol)
    if config is None:
        flash(f"Config file for '{name}' not found", "error")
        return redirect(url_for("main.dashboard"))

    ext = ".conf" if protocol == "wireguard" else ".ovpn"
    filename = f"{name}{ext}"

    return send_file(
        io.BytesIO(config.encode("utf-8")),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=filename,
    )


@main.route("/clients/<name>/config")
@login_required
def view_config(name: str):
    if not _validate_client_name(name):
        return {"error": "Invalid client name"}, 400
    protocol = request.args.get("protocol", "")
    config = get_client_config(name, protocol)
    if config is None:
        return {"error": "Config not found"}, 404
    return {"name": name, "config": config}
