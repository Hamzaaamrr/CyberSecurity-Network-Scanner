import test
import scapy.all as scapy

def net_scan(net):
    arp_request = scapy.ARP(pdst=net)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_broadcast_req = broadcast / arp_request
    ans, unans = scapy.srp(arp_broadcast_req, timeout=2, verbose=False)

    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        vendor = test.get_vendor(mac)
        
        hostname, _ = test.query_hosts(ip)
        if not hostname:
            hostname = test.query_socket(ip)
        if not hostname:
            hostname = test.query_nslookup(ip)
        
        if hostname:
            print(f"IP: {ip}  MAC: {mac}  Hostname: {hostname}  Vendor: {vendor}")
        else:
            print(f"IP: {ip}  MAC: {mac}  Hostname: [Not Found]  Vendor: {vendor}")

    return ans, unans


network = '192.168.1.0/24' #provide subnet mask here
print(f"[*] Detected network: {network}")
net_scan(network)