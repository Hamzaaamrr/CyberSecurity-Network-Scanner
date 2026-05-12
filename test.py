# pyrefly: ignore [missing-import]

import os
import re
import socket
import subprocess

# pyrefly: ignore [missing-import]
from mac_vendor_lookup import MacLookup


# ─────────────────────────────────────────────────────────────
# Vendor Lookup
# ─────────────────────────────────────────────────────────────

def get_vendor(mac):

    try:

        if not mac:
            return "Unknown"

        # Randomized/private MAC detection
        if len(mac) > 1 and mac[1].upper() in ['2', '6', 'A', 'E']:
            return "Private/Randomized MAC"

        return MacLookup().lookup(mac)

    except:
        return "Unknown"


# ─────────────────────────────────────────────────────────────
# Hosts File Lookup
# ─────────────────────────────────────────────────────────────

HOSTS_PATHS = [
    "/etc/hosts",
    "C:\\Windows\\System32\\drivers\\etc\\hosts"
]


def query_hosts(address):

    hosts = {}

    for path in HOSTS_PATHS:

        if os.path.isfile(path):

            try:

                with open(path, "r") as f:
                    lines = f.readlines()

                for line in lines:

                    line = line.strip()

                    if not line or line.startswith("#"):
                        continue

                    parts = line.split()

                    if len(parts) >= 2:
                        hosts[parts[0]] = parts[1].split(".")[0]

            except:
                pass

    return hosts.get(address), path


# ─────────────────────────────────────────────────────────────
# nslookup
# ─────────────────────────────────────────────────────────────

def query_nslookup(address):

    try:

        result = subprocess.run(
            f"nslookup {address}",
            shell=True,
            capture_output=True,
            text=True
        )

        output = result.stdout

        exp = re.compile(r"Name:\s*(.*)", re.I)

        for line in output.split("\n"):

            match = exp.search(line)

            if match:
                return match.group(1).split(".")[0]

    except:
        pass

    return None


# ─────────────────────────────────────────────────────────────
# Reverse DNS
# ─────────────────────────────────────────────────────────────

def query_socket(address):

    try:

        hostname = socket.gethostbyaddr(address)[0]

        return hostname.split(".")[0]

    except:
        return None