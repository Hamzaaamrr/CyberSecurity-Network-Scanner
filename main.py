# pyrefly: ignore [missing-import]
from flask import Flask, render_template, request, redirect, url_for
import test
import scapy.all as scapy
import socket

app = Flask(__name__)

# Global variable to store last scan results
scan_results = []

def get_local_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return ".".join(local_ip.split(".")[:-1]) + ".0/24"
    except Exception:
        return '192.168.1.0/24'

def grab_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((ip, port))
        if port == 80: s.send(b"GET / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors='ignore').lower()
        s.close()
        return banner
    except: return ""

def check_ports(ip):
    # 445/135 (Win), 62078 (iOS), 5555 (Android), 8008/8009 (Android/Google)
    ports_to_check = [135, 445, 62078, 5555, 8008, 8009, 22, 80]
    open_ports = []
    os_hint = None

    for port in ports_to_check:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        if s.connect_ex((ip, port)) == 0:
            open_ports.append(port)
            if port in [135, 445]: os_hint = "Windows"
            elif port == 62078: os_hint = "iOS"
            elif port in [5555, 8008, 8009]: os_hint = "Android"
            elif port == 22:
                banner = grab_banner(ip, 22)
                if "ubuntu" in banner or "debian" in banner: os_hint = "Linux"
        s.close()
    
    return open_ports, os_hint

def perform_scan(net):
    devices = []
    arp_request = scapy.ARP(pdst=net)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_broadcast_req = broadcast / arp_request
    ans, _ = scapy.srp(arp_broadcast_req, timeout=2, verbose=False)

    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        vendor = test.get_vendor(mac)
        
        hostname, _ = test.query_hosts(ip)
        if not hostname: hostname = test.query_socket(ip)
        if not hostname: hostname = test.query_nslookup(ip)

        open_ports, system = check_ports(ip)
        
        if not system or system == "Generic Device":
            v_lower = vendor.lower()
            if "apple" in v_lower: system = "Apple Device"
            elif any(x in v_lower for x in ["samsung", "google", "huawei"]): system = "Android"
            elif "private" in v_lower: system = "Mobile (iOS/Android)"
            elif "microsoft" in v_lower: system = "Windows"

        devices.append({
            'ip': ip, 'mac': mac, 'hostname': hostname,
            'vendor': vendor, 'system': system or "Generic Device",
            'ports': ", ".join(map(str, open_ports)) if open_ports else "None"
        })
    return devices

@app.route('/')
def index():
    network = get_local_network()
    visitor_ip = request.remote_addr
    user_agent = request.user_agent.string.lower()
    
    processed_results = []
    for device in scan_results:
        d = device.copy()
        is_visitor = (d['ip'] == visitor_ip) or (visitor_ip == '127.0.0.1' and d['ip'] == get_local_network().split('/')[0])
        if is_visitor:
            if 'iphone' in user_agent: d['system'] = 'iOS (Your Device)'
            elif 'android' in user_agent: d['system'] = 'Android (Your Device)'
            elif 'windows' in user_agent: d['system'] = 'Windows (Your Device)'
            elif 'macintosh' in user_agent: d['system'] = 'macOS (Your Device)'
        
        system_lower = d['system'].lower()
        host_lower = str(d['hostname']).lower()
        if "apple" in system_lower or "mobile" in system_lower or "linux" in system_lower:
            if 'iphone' in host_lower or 'ipad' in host_lower: d['system'] = 'iOS'
            elif 'android' in host_lower: d['system'] = 'Android'
            elif 'macbook' in host_lower or 'macintosh' in host_lower: d['system'] = 'macOS'
            elif "apple" in system_lower: d['system'] = "iOS"

        processed_results.append(d)

    return render_template('index.html', devices=processed_results, network=network)

@app.route('/scan', methods=['POST'])
def scan():
    global scan_results
    network = get_local_network()
    scan_results = perform_scan(network)
    return redirect(url_for('index'))

if __name__ == "__main__":
    print(f"[*] Starting CyberScan on http://127.0.0.1:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)