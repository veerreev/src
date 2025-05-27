#!/usr/bin/env python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call
import json
import os
import threading
import time

class DDoSProtectionController(Controller):
    """Custom controller that can install flow rules to block IPs"""
    
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        self.blocked_ips = set()
        self.blocklist_file = "/home/vboxuser/Desktop/CyberPBL/CodeAVS/src/logs/blocked_ips.json"
        
    def start(self):
        """Start the controller and begin monitoring for blocklist changes"""
        super().start()
        # Start a thread to monitor blocklist changes
        monitor_thread = threading.Thread(target=self.monitor_blocklist, daemon=True)
        monitor_thread.start()
        
    def monitor_blocklist(self):
        """Monitor the blocklist file for changes and update flow rules"""
        last_modified = 0
        
        while True:
            try:
                if os.path.exists(self.blocklist_file):
                    current_modified = os.path.getmtime(self.blocklist_file)
                    
                    if current_modified > last_modified:
                        self.update_flow_rules()
                        last_modified = current_modified
                        
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                print(f"Error monitoring blocklist: {e}")
                time.sleep(5)
    
    def update_flow_rules(self):
        """Update OpenFlow rules based on current blocklist"""
        try:
            # Read current blocklist
            if os.path.exists(self.blocklist_file):
                with open(self.blocklist_file, 'r') as f:
                    blocklist = json.load(f)
                
                current_blocked_ips = {entry['ip'] for entry in blocklist}
                
                # Find newly blocked IPs
                newly_blocked = current_blocked_ips - self.blocked_ips
                
                # Find unblocked IPs
                newly_unblocked = self.blocked_ips - current_blocked_ips
                
                # Install blocking rules for newly blocked IPs
                for ip in newly_blocked:
                    self.install_blocking_rule(ip)
                    print(f"Installed blocking rule for {ip}")
                
                # Remove blocking rules for unblocked IPs
                for ip in newly_unblocked:
                    self.remove_blocking_rule(ip)
                    print(f"Removed blocking rule for {ip}")
                
                # Update our tracking set
                self.blocked_ips = current_blocked_ips
                
        except Exception as e:
            print(f"Error updating flow rules: {e}")
    
    def install_blocking_rule(self, src_ip):
        """Install OpenFlow rule to block traffic from specific IP"""
        try:
            # Block traffic from the malicious IP to host h8 (10.0.0.8)
            # Priority 1000 to ensure it takes precedence over default rules
            cmd = [
                'ovs-ofctl', 'add-flow', 's1',
                f'priority=1000,ip,nw_src={src_ip},nw_dst=10.0.0.8,actions=drop'
            ]
            call(cmd)
            
            cmd = [
                'ovs-ofctl', 'add-flow', 's2',
                f'priority=1000,ip,nw_src={src_ip},nw_dst=10.0.0.8,actions=drop'
            ]
            call(cmd)
            
            cmd = [
                'ovs-ofctl', 'add-flow', 's3',
                f'priority=1000,ip,nw_src={src_ip},nw_dst=10.0.0.8,actions=drop'
            ]
            call(cmd)
            
            cmd = [
                'ovs-ofctl', 'add-flow', 's4',
                f'priority=1000,ip,nw_src={src_ip},nw_dst=10.0.0.8,actions=drop'
            ]
            call(cmd)
            
        except Exception as e:
            print(f"Error installing blocking rule for {src_ip}: {e}")
    
    def remove_blocking_rule(self, src_ip):
        """Remove OpenFlow rule that blocks traffic from specific IP"""
        try:
            # Remove the blocking rule from all switches
            switches = ['s1', 's2', 's3', 's4']
            for switch in switches:
                cmd = [
                    'ovs-ofctl', 'del-flows', switch,
                    f'ip,nw_src={src_ip},nw_dst=10.0.0.8'
                ]
                call(cmd)
                
        except Exception as e:
            print(f"Error removing blocking rule for {src_ip}: {e}")

def setup_initial_flows(net):
    """Setup initial flow rules for basic connectivity"""
    info('*** Setting up initial flow rules\n')
    
    switches = ['s1', 's2', 's3', 's4']
    
    for switch in switches:
        # Allow ARP traffic (essential for network discovery)
        call(['ovs-ofctl', 'add-flow', switch, 'priority=2000,arp,actions=FLOOD'])
        
        # Allow ICMP (ping) traffic for testing
        call(['ovs-ofctl', 'add-flow', switch, 'priority=1500,icmp,actions=NORMAL'])
        
        # Default rule for other traffic (lower priority)
        call(['ovs-ofctl', 'add-flow', switch, 'priority=100,actions=NORMAL'])

def setup_host_monitoring(net):
    """Setup monitoring capabilities on target host"""
    info('*** Setting up host monitoring\n')
    
    # Enable IP forwarding on host h8 (target host)
    h8 = net.get('h8')
    h8.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    
    # Setup iptables logging for monitoring (optional)
    h8.cmd('iptables -F')  # Clear existing rules
    h8.cmd('iptables -A INPUT -p tcp --dport 80 -j ACCEPT')  # Allow HTTP
    h8.cmd('iptables -A INPUT -p tcp --dport 22 -j ACCEPT')  # Allow SSH
    
def create_attack_scenario_helpers(net):
    """Create helper functions for simulating attacks"""
    info('*** Setting up attack simulation helpers\n')
    
    # Create a simple HTTP server on h8 for testing
    h8 = net.get('h8')
    h8.cmd('python3 -m http.server 80 &')
    
    print("Attack simulation commands:")
    print("To simulate SYN flood from h1: mininet> h1 hping3 -S -p 80 --flood 10.0.0.8")
    print("To simulate SYN flood from h2: mininet> h2 hping3 -S -p 80 --flood 10.0.0.8")
    print("To test connectivity: mininet> h1 ping 10.0.0.8")

def myNetwork():
    """Create and configure the network topology with DDoS protection"""
    
    net = Mininet(topo=None,
                  build=False,
                  ipBase='10.0.0.0/8')

    info('*** Adding DDoS Protection Controller\n')
    # Use our custom controller with DDoS protection capabilities
    c0 = net.addController(name='c0',
                          controller=DDoSProtectionController,
                          protocol='tcp',
                          port=6633)

    info('*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)

    info('*** Add hosts\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    h4 = net.addHost('h4', cls=Host, ip='10.0.0.4', defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='10.0.0.5', defaultRoute=None)
    h6 = net.addHost('h6', cls=Host, ip='10.0.0.6', defaultRoute=None)
    h7 = net.addHost('h7', cls=Host, ip='10.0.0.7', defaultRoute=None)
    h8 = net.addHost('h8', cls=Host, ip='10.0.0.8', defaultRoute=None)  # Target host

    info('*** Add links\n')
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, s4)
    net.addLink(s1, h1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(h5, s3)
    net.addLink(h6, s3)
    net.addLink(h7, s4)
    net.addLink(h8, s4)  # Target host connected to s4

    info('*** Starting network\n')
    net.build()
    
    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info('*** Starting switches\n')
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])

    info('*** Post configure switches and hosts\n')
    
    # Setup initial flow rules
    setup_initial_flows(net)
    
    # Setup monitoring on target host
    setup_host_monitoring(net)
    
    # Create attack simulation helpers
    create_attack_scenario_helpers(net)
    
    info('\n*** Network ready with DDoS protection enabled\n')
    info('*** Target host: h8 (10.0.0.8)\n')
    info('*** Monitoring interface: h8-eth0\n')
    info('*** Run detection script: python3 realtime_attack_detection.py\n')
    info('*** Start web dashboard: python3 app.py\n\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()