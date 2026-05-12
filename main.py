# pyrefly: ignore [missing-import]
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
    """Filters out IPs and garbage from hostnames"""
    if not name: return "Unknown"
    name = str(name).strip().split(".")[0]
    
    # Reject if it's just an IP address or matches the IP
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", name): return "Unknown"
    if name == ip or name.startswith(ip.split(".")[0]): 
        # Check if the whole thing looks like an IP
        if all(c.isdigit() or c == '.' for c in name): return "Unknown"
        
    # Clean characters
    name = re.sub(r'[^a-zA-Z0-9\-_]', '', name)
    return name if name else "Unknown"

# ── Discovery Engine ─────────────────────────────────────────────────────────

def ping_host(ip):
    """Standard ping method using subprocess"""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        result = subprocess.run(["ping", param, "1", "-w", "400", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return ip if result.returncode == 0 else None
    except: return None

def arp_scan(network):
    """Hardware-level discovery using ARP"""
    try:
        req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=network)
        ans, _ = scapy.srp(req, timeout=2, verbose=False)
        return {rcv.psrc: rcv.hwsrc for _, rcv in ans}
    except: return {}

def get_netbios_name(ip):
    """Primary method for Windows DESKTOP- names"""
    try:
        pkt = scapy.IP(dst=ip)/scapy.UDP(sport=137, dport=137)/scapy.NBNSQueryRequest(QUESTION_NAME="*", QUESTION_TYPE="NBSTAT")
        ans = scapy.sr1(pkt, timeout=0.7, verbose=False)
        if ans and scapy.NBNSNodeStatusResponse in ans:
            return ans[scapy.NBNSNodeStatusResponse].NODE_NAME.decode(errors='ignore').strip()
    except: pass
    return None

def get_mac_targeted(ip):
    try:
        ans = scapy.srp1(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=1.2, verbose=False)
        if ans: return ans.hwsrc
    except: pass
    return None

# ── Enrichment Logic ──────────────────────────────────────────────────────────

def check_ports(ip):
    ports = [135, 445, 62078, 5555, 8008, 8009, 1900, 22, 80]
    open_p, os_hint = [], None
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        if s.connect_ex((ip, p)) == 0:
            open_p.append(p)
            if p in [135, 445]: os_hint = "Windows"
            elif p == 62078: os_hint = "iOS"
            elif p in [5555, 8008, 8009]: os_hint = "Android"
        s.close()
    return open_p, os_hint

def enrich_device(ip, mac=None):
    if not mac: mac = get_mac_targeted(ip)
    vendor = test.get_vendor(mac) if mac else "Unknown"
    
    # Hostname: NetBIOS first (for DESKTOP- names), then gethostbyaddr
    name = get_netbios_name(ip)
    if not name:
        try: name = socket.gethostbyaddr(ip)[0]
        except: name = "Unknown"
    
    name = clean_hostname(name, ip)

    # OS Logic
    open_ports, system = check_ports(ip)
    v_low, h_low = vendor.lower(), name.lower()
    
    if ip.endswith(".1") or ip.endswith(".254") or "router" in h_low: system = "Router"
    elif not system:
        if "apple" in v_low or "iphone" in h_low: system = "iOS"
        elif "samsung" in v_low or "galaxy" in h_low: system = "Android (Samsung)"
        elif any(x in v_low or x in h_low for x in ["google", "android", "pixel", "huawei", "xiaomi"]): system = "Android"
        elif "private" in v_low: system = "iOS" if 62078 in open_ports else "Android"
        elif "microsoft" in v_low or any(x in h_low for x in ["desktop", "laptop", "pc-"]): system = "Windows"
    
    if not system:
        try:
            p = scapy.sr1(scapy.IP(dst=ip)/scapy.ICMP(), timeout=0.4, verbose=False)
            if p: system = "Windows" if 64 < p.ttl <= 128 else "Linux / Android"
        except: pass

    return {
        "ip": ip, "mac": mac or "Unknown", "hostname": name,
        "vendor": vendor, "system": system or "Generic Device",
        "ports": ", ".join(map(str, open_ports)) if open_ports else "None",
    }

# ── Main ─────────────────────────────────────────────────────────────────────

def perform_scan(network):
    print(f"[*] Starting scan on {network}...")
    
    # Discovery
    ips = [str(h) for h in ipaddress.IPv4Network(network, strict=False).hosts()]
    live_ips = set()
    with ThreadPoolExecutor(max_workers=80) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in ips}
        for f in as_completed(futures):
            res = f.result()
            if res: live_ips.add(res)
            
    arp_map = arp_scan(network)
    all_ips = live_ips | set(arp_map.keys())

    devices = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futures = {ex.submit(enrich_device, ip, arp_map.get(ip)): ip for ip in all_ips}
        for f in as_completed(futures):
            devices.append(f.result())

    devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return devices

@app.route('/')
def index():
    network = get_local_network()
    visitor_ip, local_ip = request.remote_addr, get_local_ip()
    user_agent = request.user_agent.string.lower()
    
    processed = []
    for d in scan_results:
        device = d.copy()
        is_me = (device['ip'] == visitor_ip) or (visitor_ip == '127.0.0.1' and device['ip'] == local_ip)
        if is_me:
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
    print("[*] CyberScan running on http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)