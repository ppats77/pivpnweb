"""Core PiVPN service layer.

Interfaces with PiVPN configuration files and CLI to manage VPN clients.
Supports both OpenVPN and WireGuard protocols.
"""
import os
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


# --- Configuration -----------------------------------------------------------

OPENVPN_SETUP_VARS = "/etc/pivpn/openvpn/setupVars.conf"
WIREGUARD_SETUP_VARS = "/etc/pivpn/wireguard/setupVars.conf"

OPENVPN_INDEX = "/etc/openvpn/easy-rsa/pki/index.txt"
OPENVPN_STATUS_LOG = "/var/log/openvpn-status.log"
OPENVPN_CCD_DIR = "/etc/openvpn/ccd"

WIREGUARD_CONF = "/etc/wireguard/wg0.conf"
WIREGUARD_CLIENTS_TXT = "/etc/wireguard/configs/clients.txt"
WIREGUARD_CONFIGS_DIR = "/etc/wireguard/configs"


# --- Data classes ------------------------------------------------------------

@dataclass
class ConnectedClient:
    remote_ip: str = ""
    virtual_ip: str = ""
    bytes_received: str = ""
    bytes_sent: str = ""
    connected_since: str = ""


@dataclass
class VPNClient:
    name: str
    status: str = "valid"           # valid, revoked, expired, disabled
    expiry_date: str = ""
    enabled: bool = True
    connected: Optional[ConnectedClient] = None
    protocol: str = "openvpn"       # openvpn or wireguard
    public_key: str = ""
    creation_date: str = ""


# --- Setup vars --------------------------------------------------------------

def get_setup_vars() -> dict:
    """Read PiVPN setupVars.conf and return as a dict."""
    for path in [OPENVPN_SETUP_VARS, WIREGUARD_SETUP_VARS]:
        if os.path.exists(path):
            return _parse_setup_vars(path)

    # Try with sudo
    for path in [OPENVPN_SETUP_VARS, WIREGUARD_SETUP_VARS]:
        result = _sudo_read(path)
        if result is not None:
            return _parse_setup_vars_text(result)

    return {}


def _parse_setup_vars(path: str) -> dict:
    try:
        with open(path) as f:
            return _parse_setup_vars_text(f.read())
    except (PermissionError, FileNotFoundError):
        result = _sudo_read(path)
        if result is not None:
            return _parse_setup_vars_text(result)
        return {}


def _parse_setup_vars_text(text: str) -> dict:
    conf = {}
    for line in text.strip().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            conf[key.strip()] = value.strip().strip('"').strip("'")
    return conf


def _sudo_read(path: str) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["sudo", "cat", path],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode == 0:
            return proc.stdout
    except (subprocess.TimeoutExpired, OSError):
        pass
    return None


def _sudo_run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# --- Protocol detection ------------------------------------------------------

def detect_vpn_protocol() -> str:
    """Detect which VPN protocol is installed. Returns 'openvpn', 'wireguard', or 'both'."""
    has_ovpn = (
        os.path.exists(OPENVPN_SETUP_VARS)
        or _sudo_read(OPENVPN_SETUP_VARS) is not None
    )
    has_wg = (
        os.path.exists(WIREGUARD_SETUP_VARS)
        or _sudo_read(WIREGUARD_SETUP_VARS) is not None
    )

    if has_ovpn and has_wg:
        return "both"
    if has_wg:
        return "wireguard"
    if has_ovpn:
        return "openvpn"

    # Fallback: check the single setupVars we can find
    setup = get_setup_vars()
    return setup.get("VPN", "openvpn")


def get_vpn_version() -> str:
    """Get the version string of the installed VPN."""
    protocol = detect_vpn_protocol()

    if protocol in ("openvpn", "both"):
        try:
            proc = subprocess.run(
                ["openvpn", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            match = re.search(r"OpenVPN\s+([\d.]+)", proc.stdout)
            if match:
                return f"OpenVPN v{match.group(1)}"
        except (OSError, subprocess.TimeoutExpired):
            pass

    if protocol in ("wireguard", "both"):
        try:
            proc = subprocess.run(
                ["wg", "--version"],
                capture_output=True, text=True, timeout=5,
            )
            if proc.stdout.strip():
                return proc.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass

    return ""


# --- OpenVPN -----------------------------------------------------------------

def _parse_openvpn_index() -> list[dict]:
    """Parse /etc/openvpn/easy-rsa/pki/index.txt into a list of cert entries."""
    content = _sudo_read(OPENVPN_INDEX)
    if content is None:
        return []

    entries = []
    for line in content.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue

        status_flag = parts[0]  # V, R, or E
        expiry_raw = parts[1][:6]  # YYMMDD

        cn_match = re.search(r"/CN=([^/\n]+)", line)
        if not cn_match:
            continue

        cn = cn_match.group(1)

        # Skip the server certificate (first valid entry)
        entries.append({
            "status": status_flag,
            "expiry": expiry_raw,
            "cn": cn,
        })

    # Skip the first entry (server cert)
    return entries[1:] if entries else []


def _parse_openvpn_status_log() -> dict[str, ConnectedClient]:
    """Parse the OpenVPN status log for connected clients."""
    content = _sudo_read(OPENVPN_STATUS_LOG)
    if content is None:
        return {}

    clients: dict[str, ConnectedClient] = {}
    for line in content.strip().splitlines():
        if not line.startswith("CLIENT_LIST"):
            continue

        parts = line.split("\t")
        if len(parts) < 8:
            # Try comma separation
            parts = line.split(",")
        if len(parts) < 8:
            continue

        cn = parts[1]
        remote = parts[2].split(":")[0] if ":" in parts[2] else parts[2]
        virtual_ip = parts[3]
        bytes_recv = parts[4]
        bytes_sent = parts[5]
        connected_since = parts[6]
        if len(parts) > 7:
            connected_since = f"{parts[6]} {parts[7]}"

        clients[cn] = ConnectedClient(
            remote_ip=remote,
            virtual_ip=virtual_ip,
            bytes_received=_format_bytes(bytes_recv),
            bytes_sent=_format_bytes(bytes_sent),
            connected_since=connected_since,
        )

    return clients


def _check_openvpn_ccd_enabled(name: str) -> bool:
    """Check if a client is enabled by reading their CCD file."""
    content = _sudo_read(f"{OPENVPN_CCD_DIR}/{name}")
    if content is None:
        return True  # No CCD file means enabled by default

    lines = content.strip().splitlines()
    if len(lines) >= 2:
        # If second line starts with #, client is disabled
        return not lines[1].strip().startswith("#")
    # Check if first line has 0.0.0.1 (disabled IP)
    if lines and "0.0.0.1" in lines[0]:
        return False
    return True


def list_openvpn_clients() -> list[VPNClient]:
    """List all OpenVPN clients with their status and connection info."""
    entries = _parse_openvpn_index()
    connected = _parse_openvpn_status_log()
    today = datetime.now().strftime("%y%m%d")

    clients = []
    for entry in entries:
        cn = entry["cn"]
        expiry = entry["expiry"]
        status_flag = entry["status"]

        # Determine status
        if status_flag == "R":
            status = "revoked"
        elif status_flag == "E" or expiry < today:
            status = "expired"
        else:
            status = "valid"

        # Format expiry date
        try:
            expiry_dt = datetime.strptime(f"20{expiry}", "%Y%m%d")
            expiry_formatted = expiry_dt.strftime("%b %d %Y")
        except ValueError:
            expiry_formatted = expiry

        # Check enabled status
        enabled = True
        if status == "valid":
            enabled = _check_openvpn_ccd_enabled(cn)

        # Connection info
        conn = connected.get(cn) if enabled else None

        clients.append(VPNClient(
            name=cn,
            status=status,
            expiry_date=expiry_formatted,
            enabled=enabled,
            connected=conn,
            protocol="openvpn",
        ))

    return clients


def create_openvpn_client(name: str, days: int, password: str = "") -> tuple[bool, str]:
    """Create a new OpenVPN client."""
    if password:
        cmd = ["sudo", "pivpn", "-a", "-n", name, "-p", password, "-d", str(days)]
    else:
        cmd = ["sudo", "pivpn", "-a", "nopass", "-n", name, "-d", str(days)]

    try:
        proc = _sudo_run(cmd, timeout=60)
        output = proc.stdout + proc.stderr
        return proc.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"


def enable_openvpn_client(name: str) -> tuple[bool, str]:
    """Enable a disabled OpenVPN client by restoring its CCD IP."""
    if not _is_safe_name(name):
        return False, "Invalid client name"
    ccd_path = f"{OPENVPN_CCD_DIR}/{name}"
    content = _sudo_read(ccd_path)
    if content is None:
        return False, f"CCD file not found for {name}"

    lines = content.strip().splitlines()
    if len(lines) < 2 or not lines[1].strip().startswith("#"):
        return False, "Client is not disabled"

    # Extract the commented-out IP from line 2
    ip_match = re.match(r"#([\d.]+)", lines[1].strip())
    if not ip_match:
        return False, "Could not parse stored IP"

    original_ip = ip_match.group(1)
    # Rebuild line 1 with the original IP
    new_line1 = re.sub(
        r"ifconfig-push\s+[\d.]+",
        f"ifconfig-push {original_ip}",
        lines[0],
    )
    new_content = new_line1 + "\n"

    try:
        proc = subprocess.run(
            ["sudo", "tee", ccd_path],
            input=new_content, capture_output=True, text=True, timeout=10,
        )
        return proc.returncode == 0, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"


def disable_openvpn_client(name: str) -> tuple[bool, str]:
    """Disable an OpenVPN client by replacing its CCD IP with 0.0.0.1."""
    if not _is_safe_name(name):
        return False, "Invalid client name"
    ccd_path = f"{OPENVPN_CCD_DIR}/{name}"
    content = _sudo_read(ccd_path)
    if content is None:
        return False, f"CCD file not found for {name}"

    lines = content.strip().splitlines()
    if not lines:
        return False, "CCD file is empty"

    # Extract current IP from the ifconfig-push line
    ip_match = re.search(r"ifconfig-push\s+([\d.]+)", lines[0])
    if not ip_match:
        return False, "Could not parse current IP"

    current_ip = ip_match.group(1)
    # Replace IP with 0.0.0.1 and append original IP as comment
    new_content = "ifconfig-push 0.0.0.1 255.255.255.0\n" + f"#{current_ip}\n"

    try:
        proc = subprocess.run(
            ["sudo", "tee", ccd_path],
            input=new_content, capture_output=True, text=True, timeout=10,
        )
        return proc.returncode == 0, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"


def revoke_openvpn_client(name: str) -> tuple[bool, str]:
    """Revoke/delete an OpenVPN client."""
    try:
        proc = _sudo_run(["sudo", "pivpn", "-r", "-y", name], timeout=30)
        output = proc.stdout + proc.stderr
        return proc.returncode == 0 or "Done" in output, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"


def get_openvpn_client_config(name: str) -> Optional[str]:
    """Get the .ovpn config file content for a client."""
    setup = get_setup_vars()
    user = setup.get("install_user", "")
    if not user:
        return None

    path = f"/home/{user}/ovpns/{name}.ovpn"
    content = _sudo_read(path)
    return content


def get_openvpn_config_path(name: str) -> Optional[str]:
    """Get the filesystem path to a client's .ovpn file."""
    setup = get_setup_vars()
    user = setup.get("install_user", "")
    if not user:
        return None
    return f"/home/{user}/ovpns/{name}.ovpn"


# --- WireGuard ---------------------------------------------------------------

def _parse_wireguard_clients_txt() -> list[dict]:
    """Parse /etc/wireguard/configs/clients.txt."""
    content = _sudo_read(WIREGUARD_CLIENTS_TXT)
    if content is None:
        return []

    clients = []
    for line in content.strip().splitlines():
        parts = line.split()
        if len(parts) >= 4:
            name = parts[0]
            pubkey = parts[1]
            timestamp = parts[2]
            try:
                creation = datetime.fromtimestamp(int(timestamp)).strftime("%b %d %Y")
            except (ValueError, OSError):
                creation = timestamp
            clients.append({
                "name": name,
                "public_key": pubkey,
                "creation_date": creation,
            })

    return clients


def _check_wireguard_disabled(name: str) -> bool:
    """Check if a WireGuard client is disabled in wg0.conf."""
    content = _sudo_read(WIREGUARD_CONF)
    if content is None:
        return False

    pattern = rf"#\[disabled\]\s*###\s*begin\s+{re.escape(name)}\s*###"
    return bool(re.search(pattern, content))


def _get_wireguard_connected() -> dict[str, ConnectedClient]:
    """Get connected WireGuard clients via wg show."""
    try:
        proc = _sudo_run(["sudo", "wg", "show", "wg0", "dump"], timeout=10)
        if proc.returncode != 0:
            return {}
    except (subprocess.TimeoutExpired, OSError):
        return {}

    # Cross-reference pubkeys with client names
    clients_txt = _parse_wireguard_clients_txt()
    pubkey_map = {c["public_key"]: c["name"] for c in clients_txt}

    connected: dict[str, ConnectedClient] = {}
    for line in proc.stdout.strip().splitlines()[1:]:  # Skip server line
        parts = line.split("\t")
        if len(parts) < 7:
            continue

        pubkey = parts[0]
        endpoint = parts[2]
        last_handshake = parts[4]
        bytes_recv = parts[5]
        bytes_sent = parts[6]

        name = pubkey_map.get(pubkey, "")
        if not name:
            continue

        # Only show as connected if there's been a recent handshake
        try:
            hs_time = int(last_handshake)
            if hs_time == 0:
                continue
            since = datetime.fromtimestamp(hs_time).strftime("%Y-%m-%d %H:%M:%S")
            # Consider connected if handshake within last 3 minutes
            if time.time() - hs_time > 180:
                continue
        except (ValueError, OSError):
            continue

        remote = endpoint.split(":")[0] if ":" in endpoint else endpoint

        connected[name] = ConnectedClient(
            remote_ip=remote,
            virtual_ip="",
            bytes_received=_format_bytes(bytes_recv),
            bytes_sent=_format_bytes(bytes_sent),
            connected_since=since,
        )

    return connected


def list_wireguard_clients() -> list[VPNClient]:
    """List all WireGuard clients."""
    clients_data = _parse_wireguard_clients_txt()
    connected = _get_wireguard_connected()

    clients = []
    for c in clients_data:
        name = c["name"]
        disabled = _check_wireguard_disabled(name)

        conn = connected.get(name) if not disabled else None

        clients.append(VPNClient(
            name=name,
            status="valid",
            expiry_date="",
            enabled=not disabled,
            connected=conn,
            protocol="wireguard",
            public_key=c["public_key"],
            creation_date=c["creation_date"],
        ))

    return clients


def create_wireguard_client(name: str) -> tuple[bool, str]:
    """Create a new WireGuard client."""
    try:
        proc = _sudo_run(["sudo", "pivpn", "-a", "-n", name], timeout=30)
        output = proc.stdout + proc.stderr
        return proc.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"


def enable_wireguard_client(name: str) -> tuple[bool, str]:
    """Enable a disabled WireGuard client."""
    try:
        proc = _sudo_run(["sudo", "pivpn", "-on", name, "-y"], timeout=15)
        output = proc.stdout + proc.stderr
        return proc.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"


def disable_wireguard_client(name: str) -> tuple[bool, str]:
    """Disable a WireGuard client."""
    try:
        proc = _sudo_run(["sudo", "pivpn", "-off", name, "-y"], timeout=15)
        output = proc.stdout + proc.stderr
        return proc.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"


def revoke_wireguard_client(name: str) -> tuple[bool, str]:
    """Remove a WireGuard client."""
    try:
        proc = _sudo_run(["sudo", "pivpn", "-r", name, "-y"], timeout=30)
        output = proc.stdout + proc.stderr
        return proc.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"


def get_wireguard_client_config(name: str) -> Optional[str]:
    """Get the WireGuard config file content for a client."""
    setup = get_setup_vars()
    user = setup.get("install_user", "")
    if not user:
        return None

    path = f"/home/{user}/configs/{name}.conf"
    content = _sudo_read(path)
    if content is None:
        # Fallback to /etc/wireguard/configs/
        content = _sudo_read(f"{WIREGUARD_CONFIGS_DIR}/{name}.conf")
    return content


def get_wireguard_config_path(name: str) -> Optional[str]:
    """Get the filesystem path to a client's WireGuard config."""
    setup = get_setup_vars()
    user = setup.get("install_user", "")
    if not user:
        return None
    return f"/home/{user}/configs/{name}.conf"


# --- Unified interface -------------------------------------------------------

def list_clients() -> list[VPNClient]:
    """List all VPN clients for the detected protocol."""
    protocol = detect_vpn_protocol()

    clients = []
    if protocol in ("openvpn", "both"):
        clients.extend(list_openvpn_clients())
    if protocol in ("wireguard", "both"):
        clients.extend(list_wireguard_clients())

    return clients


def create_client(name: str, days: int = 1080, password: str = "") -> tuple[bool, str]:
    protocol = detect_vpn_protocol()
    if protocol == "wireguard":
        return create_wireguard_client(name)
    return create_openvpn_client(name, days, password)


def enable_client(name: str, protocol: str = "") -> tuple[bool, str]:
    if not protocol:
        protocol = detect_vpn_protocol()
    if protocol == "wireguard":
        return enable_wireguard_client(name)
    return enable_openvpn_client(name)


def disable_client(name: str, protocol: str = "") -> tuple[bool, str]:
    if not protocol:
        protocol = detect_vpn_protocol()
    if protocol == "wireguard":
        return disable_wireguard_client(name)
    return disable_openvpn_client(name)


def revoke_client(name: str, protocol: str = "") -> tuple[bool, str]:
    if not protocol:
        protocol = detect_vpn_protocol()
    if protocol == "wireguard":
        return revoke_wireguard_client(name)
    return revoke_openvpn_client(name)


def get_client_config(name: str, protocol: str = "") -> Optional[str]:
    if not protocol:
        protocol = detect_vpn_protocol()
    if protocol == "wireguard":
        return get_wireguard_client_config(name)
    return get_openvpn_client_config(name)


def get_config_path(name: str, protocol: str = "") -> Optional[str]:
    if not protocol:
        protocol = detect_vpn_protocol()
    if protocol == "wireguard":
        return get_wireguard_config_path(name)
    return get_openvpn_config_path(name)


# --- Helpers -----------------------------------------------------------------

def _is_safe_name(name: str) -> bool:
    """Validate that a client name is safe for use in file paths and commands."""
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9._@-]*$", name))


def _format_bytes(b: str) -> str:
    """Format bytes into human-readable form."""
    try:
        n = int(b)
    except (ValueError, TypeError):
        return b

    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
