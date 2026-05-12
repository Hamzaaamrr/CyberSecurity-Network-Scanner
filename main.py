from flask import Flask, render_template, request, redirect, url_for
import test
import scapy.all as scapy
import socket
import ipaddress
import re
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
scan_results = []

# ── Network Helpers ────────────────────────────────────────────────────────────

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except: return "127.0.0.1"

def get_local_network():
    ip = get_local_ip()
    return ".".join(ip.split(".")[:-1]) + ".0/24"

def clean_hostname(name, ip):
    if not name or name == "Unknown": return "Unknown"
    name = str(name).strip().split(".")[0]
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", name): return "Unknown"
    name = re.sub(r'[^a-zA-Z0-9\-_]', '', name)
    return name if name else "Unknown"

# ── Discovery Engine ─────────────────────────────────────────────────────────

def arp_scan(network):
    """The most reliable way to find local devices."""
    try:
        # Send ARP broadcast to the whole subnet
        ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=network), timeout=2, verbose=False)
        return {rcv.psrc: rcv.hwsrc for _, rcv in ans}
    except PermissionError:
        print("[!] Error: Scapy requires Admin/Sudo privileges for ARP scanning.")
        return {}
    except: return {}

def ping_fallback(ip):
    """Used only if ARP fails or for non-local segments."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(["ping", param, "1", "-w", "500", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ip if result.returncode == 0 else None
    except: return None

# ── Enrichment Logic ──────────────────────────────────────────────────────────

def check_ports(ip):
    ports = [135, 445, 62078, 5555, 8008, 8009, 22, 80]
    open_p, os_hint = [], None
    for p in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            if s.connect_ex((ip, p)) == 0:
                open_p.append(p)
                if p in [135, 445]: os_hint = "Windows"
                elif p == 62078: os_hint = "iOS"
                elif p in [5555, 8008, 8009]: os_hint = "Android/Google"
    return open_p, os_hint

def enrich_device(ip, mac=None):
    # 1. Hostname Lookup (Hierarchy: NetBIOS -> Hosts -> nslookup -> Socket)
    name = None
    try:
        # Try NetBIOS via Scapy
        pkt = scapy.IP(dst=ip)/scapy.UDP(sport=137, dport=137)/scapy.NBNSQueryRequest(QUESTION_NAME="*", QUESTION_TYPE="NBSTAT")
        ans = scapy.sr1(pkt, timeout=0.5, verbose=False)
        if ans and scapy.NBNSNodeStatusResponse in ans:
            name = ans[scapy.NBNSNodeStatusResponse].NODE_NAME.decode(errors='ignore').strip()
    except: pass

    if not name: name = test.query_hosts(ip)
    if not name: name = test.query_nslookup(ip)
    if not name: name = test.query_socket(ip)
    
    hostname = clean_hostname(name, ip)
    
    # 2. Vendor & OS Detection
    vendor = test.get_vendor(mac) if mac else "Unknown"
    open_ports, system = check_ports(ip)
    
    v_low, h_low = vendor.lower(), hostname.lower()
    if ip.endswith(".1") or "router" in h_low: system = "Router"
    elif not system:
        if "apple" in v_low or "iphone" in h_low: system = "iOS"
        elif "samsung" in v_low or "google" in v_low or "android" in h_low: system = "Android"
        elif "microsoft" in v_low or "desktop" in h_low: system = "Windows"

    return {
        "ip": ip, "mac": mac or "Unknown", "hostname": hostname,
        "vendor": vendor, "system": system or "Generic Device",
        "ports": ", ".join(map(str, open_ports)) if open_ports else "None",
    }

# ── Main ─────────────────────────────────────────────────────────────────────

def perform_scan(network):
    print(f"[*] Scanning {network}...")
    
    # Discovery Phase
    arp_results = arp_scan(network)
    live_ips = set(arp_results.keys())
    
    # If ARP is empty (maybe permissions?), try a quick threaded ping
    if not live_ips:
        ips = [str(h) for h in ipaddress.IPv4Network(network, strict=False).hosts()]
        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = [ex.submit(ping_fallback, ip) for ip in ips]
            for f in as_completed(futures):
                res = f.result()
                if res: live_ips.add(res)

    # Enrichment Phase
    devices = []
    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = [ex.submit(enrich_device, ip, arp_results.get(ip)) for ip in live_ips]
        for f in as_completed(futures):
            devices.append(f.result())

    devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return devices

@app.route('/')
def index():
    network = get_local_network()
    visitor_ip = request.remote_addr
    local_ip = get_local_ip()
    user_agent = request.user_agent.string.lower()
    
    processed = []
    for d in scan_results:
        device = d.copy()
        # Mark the device as 'Your Device' if IPs match
        if device['ip'] == visitor_ip or (visitor_ip == '127.0.0.1' and device['ip'] == local_ip):
            if 'iphone' in user_agent: device['system'] = 'iOS (Your Device)'
            elif 'android' in user_agent: device['system'] = 'Android (Your Device)'
            elif 'windows' in user_agent: device['system'] = 'Windows (Your Device)'
            elif 'macintosh' in user_agent: device['system'] = 'macOS (Your Device)'
        processed.append(device)

    return render_template('index.html', devices=processed, network=network)

@app.route('/scan', methods=['POST'])
def scan():
    global scan_results
    scan_results = perform_scan(get_local_network())
    return redirect(url_for('index'))

if __name__ == "__main__":
    # Reminder: Run with sudo/Admin for Scapy to work!
    app.run(debug=True, host='0.0.0.0', port=5000)