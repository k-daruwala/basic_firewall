#!/usr/bin/env python3
"""
Basic Firewall Implementation using Python
Demonstrates packet filtering and network security concepts
Requires: scapy library and root/administrator privileges
"""

from scapy.all import *
from datetime import datetime
import json
import os

class BasicFirewall:
    def __init__(self, rules_file='firewall_rules.json'):
        """Initialize the firewall with rules from a JSON file"""
        self.rules_file = rules_file
        self.blocked_ips = set()
        self.blocked_ports = set()
        self.allowed_ips = set()
        self.allowed_ports = set()
        self.default_policy = "ALLOW"  # ALLOW or BLOCK
        self.log_file = "firewall_log.txt"
        self.packet_count = 0
        self.blocked_count = 0
        
        self.load_rules()
    
    def load_rules(self):
        """Load firewall rules from JSON file"""
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, 'r') as f:
                    rules = json.load(f)
                    self.blocked_ips = set(rules.get('blocked_ips', []))
                    self.blocked_ports = set(rules.get('blocked_ports', []))
                    self.allowed_ips = set(rules.get('allowed_ips', []))
                    self.allowed_ports = set(rules.get('allowed_ports', []))
                    self.default_policy = rules.get('default_policy', 'ALLOW')
                print(f"[+] Loaded rules from {self.rules_file}")
            except Exception as e:
                print(f"[-] Error loading rules: {e}")
                self.create_default_rules()
        else:
            print(f"[!] Rules file not found. Creating default rules...")
            self.create_default_rules()
    
    def create_default_rules(self):
        """Create default firewall rules"""
        default_rules = {
            'blocked_ips': ['192.168.1.100', '10.0.0.50'],
            'blocked_ports': [23, 135, 139, 445],  # Telnet, NetBIOS, SMB
            'allowed_ips': ['192.168.1.1'],
            'allowed_ports': [80, 443, 22],  # HTTP, HTTPS, SSH
            'default_policy': 'ALLOW'
        }
        
        with open(self.rules_file, 'w') as f:
            json.dump(default_rules, f, indent=4)
        
        self.load_rules()
        print(f"[+] Created default rules file: {self.rules_file}")
    
    def log_packet(self, action, packet_info):
        """Log packet information to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {action}: {packet_info}\n"
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
    
    def analyze_packet(self, packet):
        """Analyze packet and determine if it should be allowed or blocked"""
        self.packet_count += 1
        
        # Check if packet has IP layer
        if not packet.haslayer(IP):
            return True  # Allow non-IP packets
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        # Initialize packet info
        packet_info = f"SRC: {src_ip} -> DST: {dst_ip}"
        
        # Check for TCP/UDP layers to get port information
        src_port = None
        dst_port = None
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            packet_info += f" | TCP {src_port} -> {dst_port}"
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            packet_info += f" | UDP {src_port} -> {dst_port}"
        
        # Apply firewall rules
        decision = self.apply_rules(src_ip, dst_ip, src_port, dst_port)
        
        if decision:
            self.log_packet("ALLOWED", packet_info)
            print(f"[✓] ALLOWED: {packet_info}")
        else:
            self.blocked_count += 1
            self.log_packet("BLOCKED", packet_info)
            print(f"[✗] BLOCKED: {packet_info}")
        
        return decision
    
    def apply_rules(self, src_ip, dst_ip, src_port, dst_port):
        """Apply firewall rules to determine if traffic should be allowed"""
        
        # Rule 1: Check if source IP is explicitly allowed
        if src_ip in self.allowed_ips:
            return True
        
        # Rule 2: Check if source IP is blocked
        if src_ip in self.blocked_ips:
            return False
        
        # Rule 3: Check if destination IP is blocked
        if dst_ip in self.blocked_ips:
            return False
        
        # Rule 4: Check if source port is blocked
        if src_port and src_port in self.blocked_ports:
            return False
        
        # Rule 5: Check if destination port is blocked
        if dst_port and dst_port in self.blocked_ports:
            return False
        
        # Rule 6: If port is specified and in allowed list, allow it
        if dst_port and dst_port in self.allowed_ports:
            return True
        
        # Rule 7: Apply default policy
        return self.default_policy == "ALLOW"
    
    def start_monitoring(self, interface=None, packet_count=0):
        """Start monitoring network traffic"""
        print("\n" + "="*60)
        print("         BASIC PYTHON FIREWALL - MONITORING MODE")
        print("="*60)
        print(f"[+] Default Policy: {self.default_policy}")
        print(f"[+] Blocked IPs: {', '.join(self.blocked_ips) if self.blocked_ips else 'None'}")
        print(f"[+] Blocked Ports: {', '.join(map(str, self.blocked_ports)) if self.blocked_ports else 'None'}")
        print(f"[+] Allowed IPs: {', '.join(self.allowed_ips) if self.allowed_ips else 'None'}")
        print(f"[+] Allowed Ports: {', '.join(map(str, self.allowed_ports)) if self.allowed_ports else 'None'}")
        print(f"[+] Logging to: {self.log_file}")
        print("="*60 + "\n")
        print("[*] Starting packet capture... (Press Ctrl+C to stop)")
        
        try:
            # Try Layer 2 first, fall back to Layer 3 if needed
            try:
                sniff(iface=interface, prn=self.analyze_packet, store=0, count=packet_count)
            except Exception as e:
                if "winpcap" in str(e).lower() or "libpcap" in str(e).lower():
                    print("[!] Layer 2 capture not available. Using Layer 3 (IP) mode...")
                    print("[!] Install Npcap from https://npcap.com for full functionality\n")
                    # Use Layer 3 socket for Windows without Npcap
                    sniff(prn=self.analyze_packet, store=0, count=packet_count, filter="ip")
                else:
                    raise
        except KeyboardInterrupt:
            print("\n\n[!] Stopping firewall...")
            self.print_statistics()
        except Exception as e:
            print(f"\n[-] Error: {e}")
            print("[!] Make sure you're running with administrator privileges")
            print("[!] For full packet capture on Windows, install Npcap from https://npcap.com")
    
    def print_statistics(self):
        """Print firewall statistics"""
        print("\n" + "="*60)
        print("                    FIREWALL STATISTICS")
        print("="*60)
        print(f"Total Packets Analyzed: {self.packet_count}")
        print(f"Packets Blocked: {self.blocked_count}")
        print(f"Packets Allowed: {self.packet_count - self.blocked_count}")
        if self.packet_count > 0:
            block_rate = (self.blocked_count / self.packet_count) * 100
            print(f"Block Rate: {block_rate:.2f}%")
        print("="*60)
    
    def add_blocked_ip(self, ip):
        """Add an IP address to the blocked list"""
        self.blocked_ips.add(ip)
        self.save_rules()
        print(f"[+] Added {ip} to blocked IPs")
    
    def add_blocked_port(self, port):
        """Add a port to the blocked list"""
        self.blocked_ports.add(port)
        self.save_rules()
        print(f"[+] Added port {port} to blocked ports")
    
    def remove_blocked_ip(self, ip):
        """Remove an IP address from the blocked list"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.save_rules()
            print(f"[+] Removed {ip} from blocked IPs")
        else:
            print(f"[-] {ip} not found in blocked IPs")
    
    def save_rules(self):
        """Save current rules to file"""
        rules = {
            'blocked_ips': list(self.blocked_ips),
            'blocked_ports': list(self.blocked_ports),
            'allowed_ips': list(self.allowed_ips),
            'allowed_ports': list(self.allowed_ports),
            'default_policy': self.default_policy
        }
        
        with open(self.rules_file, 'w') as f:
            json.dump(rules, f, indent=4)


def main():
    """Main function to demonstrate firewall usage"""
    print("\n" + "="*60)
    print("              BASIC PYTHON FIREWALL")
    print("="*60)
    
    # Check for root/admin privileges (cross-platform)
    import ctypes
    import sys
    
    try:
        is_admin = os.geteuid() == 0  # Linux/Mac
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows
    
    if not is_admin:
        print("\n[!] WARNING: This script requires administrator privileges")
        print("[!] Windows: Right-click Command Prompt/PowerShell and 'Run as Administrator'")
        print("[!] Linux/Mac: Run with 'sudo python3 firewall.py'")
        response = input("\n[?] Continue anyway? (y/n): ")
        if response.lower() != 'y':
            return
    
    # Create firewall instance
    firewall = BasicFirewall()
    
    # Start monitoring (capture 50 packets for demo, or use 0 for infinite)
    firewall.start_monitoring(packet_count=0)


if __name__ == "__main__":
    main()