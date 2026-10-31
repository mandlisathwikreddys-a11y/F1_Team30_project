
import ssl
import sys
import subprocess
import urllib.request
import os
from pathlib import Path


def test_https():
    """Test HTTPS using Python's normal certificate verification."""
    try:
        with urllib.request.urlopen(
            "https://www.google.com", timeout=10
        ) as response:
            print(f"HTTPS working: HTTP {response.status}")
            return True
    except Exception as exc:
        print(f"HTTPS test failed: {exc}")
        return False


def find_certificate_installer():
    """Find the Python.org certificate installer."""
    version = f"{sys.version_info.major}.{sys.version_info.minor}"

    candidates = [
        Path("/Applications") / f"Python {version}"
        / "Install Certificates.command",
        Path(sys.executable).resolve().parent
        / "Install Certificates.command",
    ]

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return None


def repair_ssl():
    print("Checking Python SSL certificates...")

    if test_https():
        print("No repair needed.")
        return

    installer = find_certificate_installer()

    if installer:
        print(f"Found certificate installer: {installer}")
        print("Running installer...")

        result = subprocess.run(["/bin/bash", str(installer)])

        if result.returncode == 0:
            print("Certificate installer finished.")
        else:
            print("Installer returned an error.")
    else:
        print("Python certificate installer not found.")
        print("Check your Python installation and certificate paths.")
        print("Python executable:", sys.executable)
        print("SSL certificate paths:", ssl.get_default_verify_paths())
        return

    print("\nTesting HTTPS again...")
    if not test_https():
        print(
            "Automatic repair did not resolve the issue. "
            "Check your network, proxy/VPN, and certificate configuration."
        )


if __name__ == "__main__":
    repair_ssl()
