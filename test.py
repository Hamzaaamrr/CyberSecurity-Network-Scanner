import sys, re, os, subprocess, socket
from mac_vendor_lookup import MacLookup

def get_vendor(mac):
    try:
        return MacLookup().lookup(mac)
    except Exception:
        return "unknown"

hosts_locs = [
  "/etc/hosts",
  "C:\\Windows\\System32\\drivers\\etc\\hosts"
  ]

hosts = {}
 
def query_hosts(address):
  #Looks for a hostname to match the given address in the hosts file.
  filename = ""
  for hosts_name in hosts_locs:
    if os.path.isfile(hosts_name):
      filename = hosts_name
      lines = open(hosts_name).readlines()
      slines = [line.split() for line in lines]
      for sline in slines:
        if (len(sline) > 1) and (sline[0][0] != "#") :
          hosts[sline[0]] = sline[1].split(".")[0]
      break
  if not hosts:
    print("[lookup]: We could not find any hosts file. We looked in:")
    for hosts_name in hosts_locs:
      print("[lookup]:\t - %s"%hosts_name)
    return None, None
  elif address in hosts:
      return hosts[address],filename
  else:
      return None,filename



def query_nslookup(address):
  #contacts DNS Server to find hostname from IP address

  result = subprocess.run("nslookup %s"%address, shell=True, capture_output=True, text=True)
  results = result.stdout
  exp = re.compile(r"Name:\s*(.*)", re.M | re.I)
  for line in results.split("\n"):
    mo = exp.search(line)
    if mo:
      return mo.group(1).split(".")[0]
  return None



def query_socket(address):
  #Uses socket.gethostbyaddr() to get hostname from IP address.
  try:
    hostname = socket.gethostbyaddr(address)[0]
    return hostname.split(".")[0]
  except (socket.herror, socket.gaierror, OSError):
    return None



