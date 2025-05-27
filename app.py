from flask import Flask, render_template, jsonify, request
import json
import time
import os
import subprocess

app = Flask(__name__)

# Path to the JSON log file and blocklist file
LOG_FILE = "/home/vboxuser/Desktop/CyberPBL/CodeAVS/src/logs/detection_logs.json"
BLOCKLIST_FILE = "/home/vboxuser/Desktop/CyberPBL/CodeAVS/src/logs/blocked_ips.json"
PENDING_BLOCKS_FILE = "/home/vboxuser/Desktop/CyberPBL/CodeAVS/src/logs/pending_blocks.json"

# Ensure the log file exists and is initialized
def initialize_log_file():
    if not os.path.exists(LOG_FILE) or os.path.getsize(LOG_FILE) == 0:
        with open(LOG_FILE, 'w') as f:
            json.dump([], f)
        os.chmod(LOG_FILE, 0o777)

# Ensure the blocklist file exists and is initialized
def initialize_blocklist_file():
    if not os.path.exists(BLOCKLIST_FILE) or os.path.getsize(BLOCKLIST_FILE) == 0:
        with open(BLOCKLIST_FILE, 'w') as f:
            json.dump([], f)
        os.chmod(BLOCKLIST_FILE, 0o777)

# Ensure the pending blocks file exists and is initialized
def initialize_pending_blocks_file():
    if not os.path.exists(PENDING_BLOCKS_FILE) or os.path.getsize(PENDING_BLOCKS_FILE) == 0:
        with open(PENDING_BLOCKS_FILE, 'w') as f:
            json.dump([], f)
        os.chmod(PENDING_BLOCKS_FILE, 0o777)

# Function to read current blocklist
def get_blocklist():
    try:
        with open(BLOCKLIST_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading blocklist: {e}")
        return []

# Function to read pending blocks
def get_pending_blocks():
    try:
        with open(PENDING_BLOCKS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading pending blocks: {e}")
        return []

# Function to remove IP from iptables and blocklist
def unblock_ip(ip_address):
    try:
        print(f"Attempting to unblock IP: {ip_address}")
        
        # Remove from iptables (try both possible rule formats)
        commands_to_try = [
            ['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'],
            ['sudo', 'iptables', '-D', 'INPUT', '-s', f"{ip_address}/32", '-j', 'DROP']
        ]
        
        iptables_success = False
        for cmd in commands_to_try:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"Successfully removed iptables rule for {ip_address}")
                    iptables_success = True
                    break
                else:
                    print(f"Command failed: {' '.join(cmd)}, stderr: {result.stderr}")
            except subprocess.TimeoutExpired:
                print(f"Command timed out: {' '.join(cmd)}")
            except Exception as e:
                print(f"Error running command {' '.join(cmd)}: {e}")
        
        if not iptables_success:
            print(f"Warning: Could not remove iptables rule for {ip_address}, but continuing with file cleanup")
        
        # Remove from blocklist file
        blocklist = get_blocklist()
        original_length = len(blocklist)
        
        # Handle both dict and string formats in blocklist
        updated_blocklist = []
        for entry in blocklist:
            if isinstance(entry, dict):
                if entry.get('ip') != ip_address:
                    updated_blocklist.append(entry)
            elif isinstance(entry, str):
                if entry != ip_address:
                    updated_blocklist.append(entry)
            else:
                # Keep unknown formats as-is
                updated_blocklist.append(entry)
        
        # Write updated blocklist
        with open(BLOCKLIST_FILE, 'w') as f:
            json.dump(updated_blocklist, f, indent=4)
        
        print(f"Blocklist updated: removed {original_length - len(updated_blocklist)} entries")
        
        # Also remove from pending blocks if present
        pending_blocks = get_pending_blocks()
        original_pending_length = len(pending_blocks)
        
        updated_pending = []
        for entry in pending_blocks:
            if isinstance(entry, dict):
                if entry.get('ip') != ip_address:
                    updated_pending.append(entry)
            elif isinstance(entry, str):
                if entry != ip_address:
                    updated_pending.append(entry)
            else:
                updated_pending.append(entry)
        
        with open(PENDING_BLOCKS_FILE, 'w') as f:
            json.dump(updated_pending, f, indent=4)
        
        print(f"Pending blocks updated: removed {original_pending_length - len(updated_pending)} entries")
        
        # Log the unblock action
        log_unblock_action(ip_address, iptables_success)
        
        return True
        
    except Exception as e:
        print(f"Error unblocking IP {ip_address}: {e}")
        return False

# Function to log unblock actions
def log_unblock_action(ip_address, iptables_success):
    try:
        log_entry = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "action": "IP_UNBLOCKED",
            "ip": ip_address,
            "iptables_removed": iptables_success,
            "unblocked_by": "dashboard_user"
        }
        
        # Read current logs
        try:
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        except:
            logs = []
        
        # Add new log entry
        logs.append(log_entry)
        
        # Write back to file
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=4)
        
        print(f"Logged unblock action for IP: {ip_address}")
        
    except Exception as e:
        print(f"Error logging unblock action: {e}")

# Endpoint to serve real-time data for chart updates
@app.route('/realtime_data')
def realtime_data():
    try:
        with open(LOG_FILE, 'r') as f:
            logs = json.load(f)
        if logs:
            # Return only the latest log entry
            return jsonify(logs[-1])
        else:
            return jsonify({})
    except Exception as e:
        return jsonify({"error": str(e)})

# Endpoint to serve logs
@app.route('/logs')
def logs():
    try:
        with open(LOG_FILE, 'r') as f:
            logs = json.load(f)
        return jsonify(logs)
    except Exception as e:
        return f"Error reading logs: {e}", 500

# Endpoint to serve blocklist
@app.route('/blocklist')
def blocklist():
    try:
        return jsonify(get_blocklist())
    except Exception as e:
        return jsonify({"error": str(e)})

# Endpoint to serve pending blocks
@app.route('/pending_blocks')
def pending_blocks():
    try:
        return jsonify(get_pending_blocks())
    except Exception as e:
        return jsonify({"error": str(e)})

# Endpoint to unblock an IP address
@app.route('/unblock_ip', methods=['POST'])
def unblock_ip_endpoint():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No JSON data received"})
        
        ip_address = data.get('ip')
        
        if not ip_address:
            return jsonify({"success": False, "error": "IP address is required"})
        
        print(f"Received unblock request for IP: {ip_address}")
        
        success = unblock_ip(ip_address)
        
        if success:
            return jsonify({"success": True, "message": f"IP {ip_address} has been unblocked successfully"})
        else:
            return jsonify({"success": False, "error": f"Failed to unblock IP {ip_address}"})
            
    except Exception as e:
        print(f"Error in unblock_ip_endpoint: {e}")
        return jsonify({"success": False, "error": str(e)})

# Endpoint to serve the index page
@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    initialize_log_file()  # Initialize the log file at the start
    initialize_blocklist_file()  # Initialize the blocklist file at the start
    initialize_pending_blocks_file()  # Initialize the pending blocks file at the start
    print("Flask app starting...")
    print(f"Log file: {LOG_FILE}")
    print(f"Blocklist file: {BLOCKLIST_FILE}")
    print(f"Pending blocks file: {PENDING_BLOCKS_FILE}")
    app.run(debug=True, host='0.0.0.0', port=5000)  # Run Flask app