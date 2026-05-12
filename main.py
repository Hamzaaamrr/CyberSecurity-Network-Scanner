# pyrefly: ignore [missing-import]
from flask import Flask, render_template, request, redirect, url_for
import test
import scapy.all as scapy
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

scan_results = []

# ── Network helpers ────────────────────────────────────────────────────────────

def get_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return ".".join(local_ip.split(".")[:-1]) + ".0/24"
    except Exception:
        return "192.168.1.0/24"


# ── Phase 1 — ICMP ping sweep (threaded) ──────────────────────────────────────

def ping_host(ip_str):
    """Send a single ICMP echo; return ip_str if alive, else None."""
    pkt = scapy.IP(dst=ip_str) / scapy.ICMP()
    reply = scapy.sr1(pkt, timeout=0.5, verbose=False)
    return ip_str if reply is not None else None


def ping_sweep(network, max_workers=120):
    """Ping all hosts in subnet concurrently; return set of live IPs."""
    hosts = [str(h) for h in ipaddress.IPv4Network(network, strict=False).hosts()]
    live = set()
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(ping_host, ip): ip for ip in hosts}
        for f in as_completed(futures):
            result = f.result()
            if result:
                live.add(result)
    return live


# ── Phase 2 — ARP scan ────────────────────────────────────────────────────────

def arp_scan(network):
    """Return {ip: mac} for all ARP-responding hosts."""
    req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=network)
    ans, _ = scapy.srp(req, timeout=2, verbose=False)
    return {rcv.psrc: rcv.hwsrc for _, rcv in ans}


# ── Phase 3 — Per-host detail (ports + OS hint) ───────────────────────────────

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((ip, port))
        if port == 80:
            s.send(b"GET / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").lower()
        s.close()
        return banner
    except Exception:
        return ""


def check_ports(ip):
    """Probe OS-fingerprint ports; return (open_ports_list, os_hint|None)."""
    # 445/135 → Windows | 62078 → iOS | 5555/8008/8009 → Android | 22 → Linux
    ports_to_check = [135, 445, 62078, 5555, 8008, 8009, 22, 80]
    open_ports = []
    os_hint = None

    for port in ports_to_check:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
            if port in [135, 445]:
                os_hint = "Windows"
            elif port == 62078:
                os_hint = "iOS"
            elif port in [5555, 8008, 8009]:
                os_hint = "Android"
            elif port == 22 and os_hint is None:
                banner = grab_banner(ip, 22)
                if "ubuntu" in banner or "debian" in banner:
                    os_hint = "Linux"
        s.close()

    return open_ports, os_hint


def resolve_hostname(ip):
    hostname, _ = test.query_hosts(ip)
    if not hostname:
        hostname = test.query_socket(ip)
    if not hostname:
        hostname = test.query_nslookup(ip)
    return hostname


def enrich_device(ip, mac):
    """Collect all detail for one IP; safe to run concurrently."""
    vendor = test.get_vendor(mac) if mac else "unknown"
    hostname = resolve_hostname(ip)
    open_ports, system = check_ports(ip)

    # Vendor-based OS fallback when port probing gave nothing
    if not system:
        v = vendor.lower()
        if "apple" in v:
            system = "Apple Device"
        elif any(x in v for x in ["samsung", "google", "huawei"]):
            system = "Android"
        elif "private" in v:
            system = "Mobile (iOS/Android)"
        elif "microsoft" in v:
            system = "Windows"
        else:
            system = "Generic Device"

    return {
        "ip": ip,
        "mac": mac or "[ARP N/A]",
        "hostname": hostname,
        "vendor": vendor,
        "system": system,
        "ports": ", ".join(map(str, open_ports)) if open_ports else "None",
    }


# ── Main scan ─────────────────────────────────────────────────────────────────

def perform_scan(net):
    # 1) ICMP ping sweep — catches hosts that don't respond to ARP
    live_ips = ping_sweep(net)

    # 2) ARP scan — maps IPs → MACs, also reveals ICMP-filtered hosts
    arp_map = arp_scan(net)
    live_ips.update(arp_map.keys())   # union: both methods contribute

    # 3) Enrich every live host concurrently (hostname + ports + OS)
    devices = []
    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {
            ex.submit(enrich_device, ip, arp_map.get(ip)): ip
            for ip in live_ips
        }
        for f in as_completed(futures):
            devices.append(f.result())

    # Stable display order
    devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
    return devices


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    network = get_local_network()
    visitor_ip = request.remote_addr
    user_agent = request.user_agent.string.lower()

    processed = []
    for device in scan_results:
        d = device.copy()

        # Refine OS label for the browser making the request
        is_visitor = d["ip"] == visitor_ip or (
            visitor_ip == "127.0.0.1"
            and d["ip"] == network.split("/")[0]
        )
        if is_visitor:
            if "iphone" in user_agent:
                d["system"] = "iOS (Your Device)"
            elif "android" in user_agent:
                d["system"] = "Android (Your Device)"
            elif "windows" in user_agent:
                d["system"] = "Windows (Your Device)"
            elif "macintosh" in user_agent:
                d["system"] = "macOS (Your Device)"

        # Hostname-based OS refinement
        sys_l = d["system"].lower()
        host_l = str(d["hostname"] or "").lower()
        if any(k in sys_l for k in ("apple", "mobile", "linux")):
            if "iphone" in host_l or "ipad" in host_l:
                d["system"] = "iOS"
            elif "android" in host_l:
                d["system"] = "Android"
            elif "macbook" in host_l or "macintosh" in host_l:
                d["system"] = "macOS"
            elif "apple" in sys_l:
                d["system"] = "iOS"

        processed.append(d)

    return render_template("index.html", devices=processed, network=network)


@app.route("/scan", methods=["POST"])
def scan():
    global scan_results
    scan_results = perform_scan(get_local_network())
    return redirect(url_for("index"))


if __name__ == "__main__":
    print("[*] Starting CyberScan on http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
