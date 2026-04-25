import os
import sys
import time
import json
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP
import ctypes

# =========================
# CONFIG
# =========================
THRESHOLD = 40
SYN_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 20
TIME_WINDOW = 5

print(f"THRESHOLD: {THRESHOLD}")

# =========================
# ADMIN CHECK (Windows)
# =========================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# =========================
# UTILITIES
# =========================
def read_ip_file(filename):
    try:
        with open(filename, "r") as file:
            ips = [line.strip() for line in file if line.strip()]
        return set(ips)
    except FileNotFoundError:
        return set()

def log_event(message, ip=None, category=None):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    log_file = os.path.join(log_folder, "events.jsonl")

    event = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "category": category,
        "message": message
    }

    with open(log_file, "a") as file:
        file.write(json.dumps(event)+"\n")

# =========================
# SIGNATURE DETECTION
# =========================
SIGNATURES = [
    "get /scripts/root.exe",
    "cmd.exe",
    "union select",
    "xp_cmdshell"
]

def signature_match(packet):
    if packet.haslayer(TCP):
        payload = str(packet[TCP].payload).lower()
        for sig in SIGNATURES:
            if sig in payload:
                return sig
    return None



# =========================
# GLOBAL STATE (initialized later)
# =========================
packet_count = defaultdict(int)
connection_attempts = defaultdict(deque)
syn_tracker = defaultdict(deque)
port_scan_tracker = defaultdict(lambda: deque())

blocked_ips = set()
whitelist_ips = set()
blacklist_ips = set()
block_times = {}
BLOCK_DURATION = 300

traffic_log = deque(maxlen=1000)
event_log = deque(maxlen=1000)

def rule_exists(ip):
    result = os.popen(
        'netsh advfirewall firewall show rule name=all'
    ).read()
    return f"Block_{ip}" in result

def trigger_block(ip, reason):
    if ip in blocked_ips:
        return
    
    print(f"[IPS] Blocking {ip} → {reason}")

    rule_name = f"Block_{ip}"

    if not rule_exists(ip):
        os.system(f'netsh advfirewall firewall add rule name="{rule_name}" '
                  f'dir=in action=block remoteip={ip}')
   
    log_event(reason, ip=ip, category="BLOCK")
    blocked_ips.add(ip)
    block_times[ip] = time.time()

    event_log.append({
            "time": time.time(),
            "ip": ip,
            "reason": reason
        
    })

# Detection Engine
def detection_engine(packet, src_ip):
    now = time.time()

    # Track connection attempts
    connection_attempts[src_ip].append(now)
    while connection_attempts[src_ip] and now - connection_attempts[src_ip][0] > TIME_WINDOW:
        connection_attempts[src_ip].popleft()

    rate = len(connection_attempts[src_ip]) / TIME_WINDOW
    if rate > THRESHOLD:
            trigger_block(src_ip, f"High traffic rate: {rate:.2f}/sec")
            return
    
    sig = signature_match(packet)
    if sig:
        trigger_block(src_ip, f"Signature detected: {sig}")
        return
    
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport

        port_scan_tracker[src_ip].append((dst_port,  now))
         
        while port_scan_tracker[src_ip] and now - port_scan_tracker[src_ip][0][1] > TIME_WINDOW:
            port_scan_tracker[src_ip].popleft()

        unique_ports = {p for p, t in port_scan_tracker[src_ip]}

        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            trigger_block(src_ip, "Port scan detected")
            return
        
        if packet[TCP].flags == "S":
            syn_tracker[src_ip].append(now)

            while syn_tracker[src_ip] and now - syn_tracker[src_ip][0] > TIME_WINDOW:
                syn_tracker[src_ip].popleft()

            if len(syn_tracker[src_ip]) > SYN_THRESHOLD:
                trigger_block(src_ip, "SYN flood detected")
                return
    traffic_log.append({
        "time": now,
        "src_ip": src_ip,
        "rate": rate
    })

# =========================
# PACKET HANDLER
# =========================
def packet_callback(packet):
    # Ensure IP layer exists BEFORE accessing it
    if IP not in packet:
        return

    src_ip = packet[IP].src

    # Whitelist bypass
    if src_ip in whitelist_ips:
        return

    # Blacklist enforcement
    if src_ip in blacklist_ips:
        trigger_block(src_ip, "Blacklisted IP")
        return

    detection_engine(packet, src_ip)


def cleanup_blocks():
    now = time.time()

    for ip in list(block_times.keys()):
        if now - block_times[ip] > BLOCK_DURATION:
            print(f"[IPS] Unblocking {ip}")

            os.system(f'netsh advfirewall firewall delete rule name="Block_{ip}"')

            blocked_ips.discard(ip)
            del block_times[ip]

def print_dashboard():
    os.system("cls" if os.name == "nt" else "clear")

    print("===IDS Dashboard===")
    print(f"Blocked IPs: {len(blocked_ips)}")
    print(f"Active connnections tracked: {len(connection_attempts)}")
    print(f"Recent events: {len(event_log)}")

    print("\nTop talkers:")

    top = sorted(connection_attempts.items(),
                 key=lambda x: len(x[1]),
                reverse=True)[:5]
    
    for ip, data in top:
        print(f"{ip}: {len(data)} connections")
# =========================
# MAIN
# =========================
if __name__ == "__main__":

    # Admin required
    if not is_admin():
        print("Run this script as Administrator.")
        sys.exit(1)

    # Load IP lists
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    print(f"Whitelist loaded: {len(whitelist_ips)} IPs")
    print(f"Blacklist loaded: {len(blacklist_ips)} IPs")

    print("Monitoring network traffic...")

    last_ui_update = [time.time()]

    def wrapped_sniff(packet):
        packet_callback(packet)

        cleanup_blocks()

        if time.time() - last_ui_update[0] > 2:
            print_dashboard()
            last_ui_update[0] = time.time()

    # Start sniffing
    sniff(filter="ip", prn=wrapped_sniff, store=False)