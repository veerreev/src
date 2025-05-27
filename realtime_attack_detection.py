import json
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import os
import time
import subprocess
import threading

# Initialize counters and parameters
syn_count = defaultdict(int)
ALERT_THRESHOLD = 100  # Global threshold for total SYN packets
INDIVIDUAL_IP_THRESHOLD = 22000  # Threshold for individual IP blocking
TIME_WINDOW = 10      # Time window in seconds to reset counters

# Delayed blocking parameters
GRACE_PERIOD = 30     # Time in seconds to wait before actually blocking (allows data collection)
GRACE_PACKET_THRESHOLD = 5000  # Additional packets during grace period before immediate block
SUSTAINED_RATE_THRESHOLD = 1000  # Packets per second during grace period to trigger early block

# Path to the JSON log file and blocklist file
LOG_FILE = "/home/vboxuser/Desktop/CyberPBL/CodeAVS/src/logs/detection_logs.json"
BLOCKLIST_FILE = "/home/vboxuser/Desktop/CyberPBL/CodeAVS/src/logs/blocked_ips.json"
PENDING_BLOCKS_FILE = "/home/vboxuser/Desktop/CyberPBL/CodeAVS/src/logs/pending_blocks.json"

# Ensure log directory exists
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
os.makedirs(os.path.dirname(PENDING_BLOCKS_FILE), exist_ok=True)

# Store the start time
start_time = time.time()

# Set to keep track of already blocked IPs in this session
blocked_ips = set()

# Dictionary to track pending blocks with their metadata
pending_blocks = {}

# Dictionary to track packet rates during grace period
grace_period_counts = defaultdict(lambda: {'count': 0, 'start_time': 0, 'initial_count': 0})

# Lock for thread-safe file operations
file_lock = threading.Lock()

def initialize_log_file():
    """Ensure the log file starts with valid JSON and has 777 permissions."""
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        print(f"Initializing log file: {LOG_FILE}")
        with open(LOG_FILE, 'w') as f:
            json.dump([], f)
        os.chmod(LOG_FILE, 0o777)

def initialize_blocklist_file():
    """Ensure the blocklist file starts with valid JSON."""
    if not os.path.exists(BLOCKLIST_FILE) or os.path.getsize(BLOCKLIST_FILE) == 0:
        print(f"Initializing blocklist file: {BLOCKLIST_FILE}")
        with open(BLOCKLIST_FILE, 'w') as f:
            json.dump([], f)
        os.chmod(BLOCKLIST_FILE, 0o777)

def initialize_pending_blocks_file():
    """Ensure the pending blocks file starts with valid JSON."""
    if not os.path.exists(PENDING_BLOCKS_FILE) or os.path.getsize(PENDING_BLOCKS_FILE) == 0:
        print(f"Initializing pending blocks file: {PENDING_BLOCKS_FILE}")
        with open(PENDING_BLOCKS_FILE, 'w') as f:
            json.dump([], f)
        os.chmod(PENDING_BLOCKS_FILE, 0o777)

def load_existing_blocklist():
    """Load existing blocked IPs from the blocklist file into memory."""
    try:
        if os.path.exists(BLOCKLIST_FILE):
            with file_lock:
                with open(BLOCKLIST_FILE, 'r') as f:
                    blocklist = json.load(f)
                    for entry in blocklist:
                        if isinstance(entry, dict) and 'ip' in entry:
                            blocked_ips.add(entry['ip'])
                            print(f"Loaded previously blocked IP: {entry['ip']}")
                        elif isinstance(entry, str):
                            blocked_ips.add(entry)
                            print(f"Loaded previously blocked IP: {entry}")
    except Exception as e:
        print(f"Error loading existing blocklist: {e}")

def load_existing_pending_blocks():
    """Load existing pending blocks from the pending blocks file into memory."""
    try:
        if os.path.exists(PENDING_BLOCKS_FILE):
            with file_lock:
                with open(PENDING_BLOCKS_FILE, 'r') as f:
                    pending_list = json.load(f)
                    for entry in pending_list:
                        if isinstance(entry, dict) and 'ip' in entry:
                            ip = entry['ip']
                            pending_blocks[ip] = entry
                            grace_period_counts[ip] = {
                                'count': entry.get('grace_period_count', 0),
                                'start_time': entry.get('grace_start_time', time.time()),
                                'initial_count': entry.get('initial_count', 0)
                            }
                            print(f"Loaded pending block for IP: {ip}")
    except Exception as e:
        print(f"Error loading existing pending blocks: {e}")

def write_to_log(log_entry):
    """Append a log entry to the JSON log file and print it to the terminal."""
    try:
        print(json.dumps(log_entry, indent=4))
        with file_lock:
            with open(LOG_FILE, 'r+') as f:
                logs = json.load(f)
                logs.append(log_entry)
                f.seek(0)
                json.dump(logs, f, indent=4)
                f.truncate()
    except Exception as e:
        print(f"Error writing to log file: {e}")

def update_pending_blocks_file():
    """Update the pending blocks file with current pending blocks."""
    try:
        pending_list = []
        for ip, block_info in pending_blocks.items():
            grace_info = grace_period_counts[ip]
            block_info.update({
                'grace_period_count': grace_info['count'],
                'grace_start_time': grace_info['start_time'],
                'initial_count': grace_info['initial_count']
            })
            pending_list.append(block_info)
        
        with file_lock:
            with open(PENDING_BLOCKS_FILE, 'w') as f:
                json.dump(pending_list, f, indent=4)
    except Exception as e:
        print(f"Error updating pending blocks file: {e}")

def add_to_blocklist(ip_address, reason, packet_count):
    """Add an IP address to the blocklist with timestamp and reason."""
    try:
        with file_lock:
            with open(BLOCKLIST_FILE, 'r') as f:
                blocklist = json.load(f)
            
            # Check if IP is already in blocklist
            for entry in blocklist:
                if isinstance(entry, dict) and entry.get('ip') == ip_address:
                    print(f"IP {ip_address} is already in blocklist")
                    return
                elif isinstance(entry, str) and entry == ip_address:
                    print(f"IP {ip_address} is already in blocklist")
                    return
            
            new_entry = {
                "ip": ip_address,
                "blocked_at": time.strftime('%Y-%m-%d %H:%M:%S'),
                "reason": reason,
                "packet_count": packet_count,
                "grace_period_packets": grace_period_counts[ip_address]['count'] if ip_address in grace_period_counts else 0
            }
            
            blocklist.append(new_entry)
            
            with open(BLOCKLIST_FILE, 'w') as f:
                json.dump(blocklist, f, indent=4)
            
            print(f"Added {ip_address} to blocklist: {reason}")
        
    except Exception as e:
        print(f"Error adding to blocklist: {e}")

def schedule_delayed_block(ip_address, reason, initial_packet_count):
    """Schedule an IP for delayed blocking."""
    current_time = time.time()
    
    # Add to pending blocks
    pending_blocks[ip_address] = {
        "ip": ip_address,
        "detected_at": time.strftime('%Y-%m-%d %H:%M:%S'),
        "reason": reason,
        "initial_packet_count": initial_packet_count,
        "grace_start_time": current_time,
        "status": "pending_block"
    }
    
    # Initialize grace period tracking
    grace_period_counts[ip_address] = {
        'count': 0,
        'start_time': current_time,
        'initial_count': initial_packet_count
    }
    
    # Update the pending blocks file
    update_pending_blocks_file()
    
    # Log the pending block
    pending_log_entry = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "action": "PENDING_BLOCK_SCHEDULED",
        "ip": ip_address,
        "reason": reason,
        "initial_packet_count": initial_packet_count,
        "grace_period_seconds": GRACE_PERIOD,
        "note": f"IP will be blocked after {GRACE_PERIOD} seconds or if sustained attack continues"
    }
    write_to_log(pending_log_entry)
    
    # Schedule the actual block using threading
    block_timer = threading.Timer(GRACE_PERIOD, execute_delayed_block, args=[ip_address, reason])
    block_timer.daemon = True
    block_timer.start()
    
    print(f"SCHEDULED DELAYED BLOCK for IP {ip_address}: {reason}")
    print(f"Block will execute in {GRACE_PERIOD} seconds unless conditions change")

def execute_delayed_block(ip_address, original_reason):
    """Execute the delayed block if the IP is still pending."""
    if ip_address in pending_blocks and ip_address not in blocked_ips:
        grace_info = grace_period_counts[ip_address]
        total_packets = syn_count[ip_address]
        grace_packets = grace_info['count']
        
        reason = f"Delayed block executed: {original_reason} (Grace period packets: {grace_packets}, Total: {total_packets})"
        
        success = block_ip_with_iptables(ip_address, reason, total_packets)
        
        if success:
            # Remove from pending blocks
            if ip_address in pending_blocks:
                del pending_blocks[ip_address]
            if ip_address in grace_period_counts:
                del grace_period_counts[ip_address]
            
            update_pending_blocks_file()
            
            # Log the executed block
            executed_log_entry = {
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "action": "DELAYED_BLOCK_EXECUTED",
                "blocked_ip": ip_address,
                "reason": reason,
                "total_packet_count": total_packets,
                "grace_period_packets": grace_packets
            }
            write_to_log(executed_log_entry)

def check_grace_period_conditions(ip_address):
    """Check if grace period conditions warrant immediate blocking."""
    if ip_address not in grace_period_counts:
        return False
    
    grace_info = grace_period_counts[ip_address]
    current_time = time.time()
    time_elapsed = current_time - grace_info['start_time']
    
    # Check if we've exceeded the grace period packet threshold
    if grace_info['count'] > GRACE_PACKET_THRESHOLD:
        reason = f"Grace period packet threshold exceeded ({grace_info['count']} packets in {time_elapsed:.1f}s)"
        execute_immediate_block_from_grace(ip_address, reason)
        return True
    
    # Check sustained rate during grace period (packets per second)
    if time_elapsed > 5:  # Only check rate after 5 seconds
        rate = grace_info['count'] / time_elapsed
        if rate > SUSTAINED_RATE_THRESHOLD:
            reason = f"Sustained high rate during grace period ({rate:.1f} packets/sec over {time_elapsed:.1f}s)"
            execute_immediate_block_from_grace(ip_address, reason)
            return True
    
    return False

def execute_immediate_block_from_grace(ip_address, reason):
    """Execute immediate block during grace period due to severe conditions."""
    grace_info = grace_period_counts[ip_address]
    total_packets = syn_count[ip_address]
    
    full_reason = f"IMMEDIATE BLOCK during grace period: {reason}"
    
    success = block_ip_with_iptables(ip_address, full_reason, total_packets)
    
    if success:
        # Remove from pending blocks
        if ip_address in pending_blocks:
            del pending_blocks[ip_address]
        if ip_address in grace_period_counts:
            del grace_period_counts[ip_address]
        
        update_pending_blocks_file()
        
        # Log the immediate block
        immediate_log_entry = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "action": "IMMEDIATE_BLOCK_FROM_GRACE",
            "blocked_ip": ip_address,
            "reason": full_reason,
            "total_packet_count": total_packets,
            "grace_period_packets": grace_info['count']
        }
        write_to_log(immediate_log_entry)
        
        print(f"IMMEDIATE BLOCK EXECUTED for {ip_address}: {reason}")

def block_ip_with_iptables(ip_address, reason, packet_count):
    """Block an IP address using iptables and add to blocklist."""
    try:
        result = subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], 
                              capture_output=True, text=True, check=True)
        
        print(f"Successfully blocked IP {ip_address} with iptables")
        
        add_to_blocklist(ip_address, reason, packet_count)
        blocked_ips.add(ip_address)
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP {ip_address} with iptables: {e}")
        print(f"stderr: {e.stderr}")
        return False
    except Exception as e:
        print(f"Error blocking IP {ip_address}: {e}")
        return False

def is_ip_blocked(ip_address):
    """Check if an IP address is already blocked."""
    return ip_address in blocked_ips

def is_ip_pending_block(ip_address):
    """Check if an IP address is pending block."""
    return ip_address in pending_blocks

def get_unblocked_syn_counts():
    """Return SYN counts only for IPs that are not blocked."""
    unblocked_counts = {}
    for ip, count in syn_count.items():
        if not is_ip_blocked(ip):
            unblocked_counts[ip] = count
    return unblocked_counts

def check_for_external_unblocks():
    """Check if any IPs have been unblocked externally and update our memory."""
    try:
        with file_lock:
            with open(BLOCKLIST_FILE, 'r') as f:
                current_blocklist = json.load(f)
        
        # Get IPs currently in file
        file_blocked_ips = set()
        for entry in current_blocklist:
            if isinstance(entry, dict) and 'ip' in entry:
                file_blocked_ips.add(entry['ip'])
            elif isinstance(entry, str):
                file_blocked_ips.add(entry)
        
        # Find IPs that were removed from file but still in memory
        memory_blocked_ips = blocked_ips.copy()
        for ip in memory_blocked_ips:
            if ip not in file_blocked_ips:
                print(f"IP {ip} was unblocked externally, updating memory")
                blocked_ips.discard(ip)
                # Also clean up related data structures
                if ip in syn_count:
                    del syn_count[ip]
                if ip in pending_blocks:
                    del pending_blocks[ip]
                if ip in grace_period_counts:
                    del grace_period_counts[ip]
        
    except Exception as e:
        print(f"Error checking for external unblocks: {e}")

def analyze_packet(packet):
    global start_time
    
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags == 'S' and packet[IP].dst == '10.0.0.8':
            src_ip = packet[IP].src
            
            # Skip processing if IP is already blocked
            if is_ip_blocked(src_ip):
                return
            
            syn_count[src_ip] += 1
            
            # If IP is in grace period, update grace period counts
            if is_ip_pending_block(src_ip):
                grace_period_counts[src_ip]['count'] += 1
                
                # Check if grace period conditions warrant immediate blocking
                if check_grace_period_conditions(src_ip):
                    return  # IP was blocked immediately, no need to continue
            
            # Check if individual IP has exceeded the threshold for the first time
            elif syn_count[src_ip] > INDIVIDUAL_IP_THRESHOLD:
                reason = f"Exceeded individual IP threshold ({INDIVIDUAL_IP_THRESHOLD} SYN packets)"
                print(f"DETECTION: IP {src_ip} exceeded threshold - scheduling delayed block")
                
                # Schedule delayed block instead of immediate block
                schedule_delayed_block(src_ip, reason, syn_count[src_ip])

            # Check the time elapsed for overall attack detection
            current_time = time.time()
            if current_time - start_time > TIME_WINDOW:
                unblocked_counts = get_unblocked_syn_counts()
                total_syns = sum(unblocked_counts.values())
                
                if total_syns > ALERT_THRESHOLD:
                    # Include pending blocks in the analysis
                    pending_ips = list(pending_blocks.keys())
                    
                    log_entry = {
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                        "alert": "Potential DDoS attack detected on host 8!",
                        "total_syns": total_syns,
                        "sources": unblocked_counts,
                        "pending_blocks": pending_ips,
                        "blocked_ips": list(blocked_ips),
                        "note": "Some IPs may be in grace period before blocking"
                    }
                    print("Alert detected:", log_entry)
                    write_to_log(log_entry)
                
                # Clear counts and reset timer
                syn_count.clear()
                start_time = current_time

def cleanup_expired_grace_periods():
    """Clean up expired grace periods and stale data."""
    while True:
        try:
            time.sleep(60)  # Run every minute
            current_time = time.time()
            expired_ips = []
            
            for ip, grace_info in grace_period_counts.items():
                if current_time - grace_info['start_time'] > GRACE_PERIOD + 10:  # 10 second buffer
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                if ip in grace_period_counts:
                    del grace_period_counts[ip]
                if ip in pending_blocks:
                    del pending_blocks[ip]
                if ip in syn_count:
                    del syn_count[ip]
                print(f"Cleaned up expired grace period data for IP: {ip}")
            
            if expired_ips:
                update_pending_blocks_file()
            
            # Also check for external unblocks
            check_for_external_unblocks()
            
        except Exception as e:
            print(f"Error in cleanup thread: {e}")

# Initialize the log files at the start
initialize_log_file()
initialize_blocklist_file()
initialize_pending_blocks_file()

# Load any existing blocked IPs and pending blocks from previous sessions
load_existing_blocklist()
load_existing_pending_blocks()

print("Starting real-time DDoS detection with DELAYED IP blocking on host 8...")
print(f"Individual IP blocking threshold: {INDIVIDUAL_IP_THRESHOLD} packets")
print(f"Global alert threshold: {ALERT_THRESHOLD} packets")
print(f"Time window: {TIME_WINDOW} seconds")
print(f"Grace period: {GRACE_PERIOD} seconds")
print(f"Grace period packet threshold: {GRACE_PACKET_THRESHOLD} packets")
print(f"Sustained rate threshold: {SUSTAINED_RATE_THRESHOLD} packets/sec")
print(f"Currently blocked IPs: {list(blocked_ips)}")
print(f"Currently pending blocks: {list(pending_blocks.keys())}")

# Start cleanup thread
cleanup_thread = threading.Thread(target=lambda: [time.sleep(60), cleanup_expired_grace_periods()], daemon=True)
cleanup_thread.start()

try:
    sniff(iface='h8-eth0', prn=analyze_packet)
except KeyboardInterrupt:
    print("\nStopping DDoS detection...")
    cleanup_expired_grace_periods()
except Exception as e:
    print(f"Error in packet sniffing: {e}")