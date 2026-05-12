import os
import re
import socket
import subprocess
from mac_vendor_lookup import MacLookup

# Initialize MacLookup once to avoid reloading it constantly
try:
    mac_lookup = MacLookup()
    # mac_lookup.update_vendors() # Uncomment this if you need to update the OUI database
except:
    mac_lookup = None

def get_vendor(mac):
    try:
        if not mac or mac == "Unknown":
            return "Unknown"
        # Randomized/private MAC detection (checking the locally administered bit)
        if len(mac) > 1 and mac[1].upper() in ['2', '6', 'A', 'E']:
            return "Private/Randomized MAC"
        return mac_lookup.lookup(mac) if mac_lookup else "Unknown"
    except:
        return "Unknown"

HOSTS_PATHS = ["/etc/hosts", "C:\\Windows\\System32\\drivers\\etc\\hosts"]

def query_hosts(address):
    for path in HOSTS_PATHS:
        if os.path.isfile(path):
            try:
                with open(path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"): continue
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == address:
                            return parts[1].split(".")[0]
            except: pass
    return None

def query_nslookup(address):
    try:
        result = subprocess.run(f"nslookup {address}", shell=True, capture_output=True, text=True, timeout=1)
        match = re.search(r"Name:\s*(.*)", result.stdout, re.I)
        if match:
            return match.group(1).strip().split(".")[0]
    except: pass
    return None

def query_socket(address):
    try:
        hostname = socket.gethostbyaddr(address)[0]
        return hostname.split(".")[0]
    except: return None