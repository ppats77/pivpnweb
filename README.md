# PiVPN Web

A Python/Flask web interface for managing PiVPN clients. Supports both **OpenVPN** and **WireGuard** protocols.

Rewrite of [pivpn-web](https://github.com/g8998/pivpn-web) from PHP to Python.

## Features

- Login with the user you installed PiVPN with
- Create new VPN clients (with optional password for OpenVPN)
- Enable / Disable clients (toggle on/off without revoking)
- Revoke / Delete clients permanently
- Download client configuration files (.ovpn / .conf)
- View and copy configuration files
- View connected clients with real-time stats (IP, bytes, connection time)
- Auto-detects installed VPN protocol (OpenVPN, WireGuard, or both)
- Responsive mobile-friendly design
- Neumorphic UI

## Requirements

- Debian / Ubuntu / Raspbian
- PiVPN installed and configured (OpenVPN and/or WireGuard)
- Python 3.10+

## Installation

### 1. Install PiVPN

```bash
curl -L https://install.pivpn.io | bash
```

### 2. Install Python and dependencies

```bash
sudo apt-get update && sudo apt-get install python3 python3-pip python3-venv git
```

### 3. Clone and set up

```bash
cd /opt
sudo git clone https://github.com/ppats77/pivpnweb.git pivpn-web
cd pivpn-web

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Configure sudo permissions

Create `/etc/sudoers.d/pivpn-web`:

```bash
YOUR_USERNAME ALL=(ALL) NOPASSWD: /bin/cat, /bin/sed, /usr/local/bin/pivpn, /usr/bin/wg
```

### 5. Run

**Development:**
```bash
python run.py
```

**Production (with gunicorn):**
```bash
gunicorn --bind 0.0.0.0:8080 --workers 2 run:app
```

### 6. Access

Open your browser to `http://YOUR_IP:8080` and sign in with your PiVPN user credentials.

## Docker

```bash
docker compose up -d
```

Note: The container needs host network mode and privileged access to interact with PiVPN.

## Systemd Service

Create `/etc/systemd/system/pivpn-web.service`:

```ini
[Unit]
Description=PiVPN Web
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/opt/pivpn-web
ExecStart=/opt/pivpn-web/venv/bin/gunicorn --bind 0.0.0.0:8080 --workers 2 run:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pivpn-web
```

## Project Structure

```
pivpn-web/
├── run.py                    # Entry point
├── run_dev.py                # Dev mode launcher (mock data)
├── requirements.txt          # Python dependencies
├── Dockerfile
├── docker-compose.yml
├── dev/                      # Mock data for local testing
├── app/
│   ├── __init__.py           # Flask app factory
│   ├── auth.py               # Authentication (PAM/su)
│   ├── routes.py             # Flask routes/views
│   ├── services/
│   │   └── pivpn.py          # PiVPN service layer (OpenVPN + WireGuard)
│   ├── templates/
│   │   ├── base.html         # Base template
│   │   ├── login.html        # Login page
│   │   └── dashboard.html    # Main dashboard
│   └── static/
│       ├── css/
│       │   ├── index.css     # Dashboard styles
│       │   └── login.css     # Login styles
│       ├── js/
│       │   ├── checkName.js  # Client name validation
│       │   ├── show-form.js  # Popup form handling
│       │   └── mobile.js     # Mobile detection
│       └── img/              # Logo assets
└── logs/                     # Error logs
```

## Key Improvements over Original

- **Python/Flask** instead of PHP/Apache — cleaner, more maintainable
- **WireGuard support** — original was OpenVPN-only
- **Jinja2 templates** — proper template engine instead of shell-generated HTML
- **Service layer** — clean separation between web routes and PiVPN operations
- **Flash messages** — user feedback for operations
- **Config viewer API** — fetches config via AJAX instead of inline HTML
- **No inline JavaScript generation** — cleaner frontend code
- **Dev mode** — run locally with mock data for UI development

## License

MIT
