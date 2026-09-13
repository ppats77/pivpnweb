#!/usr/bin/env python3
"""Run PiVPN Web in dev mode with mock data.

Uses local ./dev/ directory as the filesystem root and bypasses system auth.
Login with: username=pi, password=anything
"""
import os
from pathlib import Path

# Point at mock data
os.environ["PIVPN_DEV"] = "1"
os.environ["PIVPN_ROOT"] = str(Path(__file__).parent / "dev")

from app import create_app

app = create_app()

if __name__ == "__main__":
    print("=" * 60)
    print("  PiVPN Web - DEV MODE")
    print("  Login: username=pi, password=anything")
    print("  http://localhost:8080")
    print("=" * 60)
    # Localhost only: the debugger allows code execution and login accepts any password
    app.run(host="127.0.0.1", port=8080, debug=True)
