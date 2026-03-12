#!/usr/bin/env python3

import subprocess
import sys
import os
import argparse
import ipaddress
import threading
import time
import json
from pathlib import Path

class AdvancedNmapScanner:
    def __init__(self, target, output_dir="nmap_recon"):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Timestamps
        self.timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        print(f"🚀 [Saahir666] Advanced Nmap Suite Initialized")
        print(f"🎯 Target: {target}")
        print(f"📁 Output: {output_dir}/")
        
    def run_nmap(self, args, name, description):
        """Execute nmap command with all output formats"""
        cmd = ["nmap"] + args + [
            "-oA", f"{self.output_dir}/{name}_{self.timestamp}"
        ]
        
        print(f"\n🔍 [{name.upper()}] {description}")
        print(f"   {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            print(f"✅ [{name.upper()}] Complete: {name}_{self.timestamp}.nmap")
            return True
        except subprocess.TimeoutExpired:
            print(f"⚠️  [{name.upper()}] TIMEOUT - skipping")
            return False
        except Exception as e:
            print(f"❌ [{name.upper()}] ERROR: {e}")
            return False
    
    def discover_network(self):
        """Auto-discover network range"""
        print("\n🌐 AUTO-NETWORK DISCOVERY")
        
        # Try common interfaces
        interfaces = ["eth0", "wlan0", "enp0s3", "wlp3s0"]
        for iface in interfaces:
            try:
                result = subprocess.run(["ip", "route", "show", "default", "dev", iface], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"✅ Network interface: {iface}")
                    # Get CIDR from route
                    route = subprocess.run(["ip", "-4", "addr", "show", iface], 
                                         capture_output=True, text=True)
                    for line in route.stdout.split('\n'):
                        if 'inet ' in line:
                            cidr = line.split('inet ')[1].split('/')[0] + '/24'
                            print(f"🎯 Auto-detected range: {cidr}")
                            return cidr
            except:
                continue
        
        # Fallback to 192.168.1.0/24
        print("🎯 Using default range: 192.168.1.0/24")
        return "192.168.1.0/24"
    
    def full_recon(self):
        """Execute complete reconnaissance suite"""
        if self.target == "auto":
            self.target = self.discover_network()
        
        # 1. HOST DISCOVERY (-sn)
        self.run_nmap(
            ["-sn", "--disable-arp-ping", "-T4", self.target],
            "host_discovery",
            "Aggressive host discovery (no ARP)"
        )
        
        # 2. TOPOLOGY + QUICK SCAN
        self.run_nmap(
            ["-sn", "--traceroute", "-T4", self.target],
            "topology_discovery", 
            "Host discovery + traceroute"
        )
        
        # 3. FULL PORT SCAN + SERVICES + OS (-A)
        self.run_nmap(
            ["-A", "-T4", "--defeat-rst-ratelimit", "-Pn", self.target],
            "aggressive_full",
            "OS detection + services + scripts + traceroute (no ping)"
        )
        
        # 4. MAC VENDOR + ARP SCAN (local network)
        self.run_nmap(
            ["-PR", "--script=broadcast-ping", "-T4", self.target],
            "mac_arp",
            "ARP + MAC vendor detection"
        )
        
        # 5. UDP SCAN (top ports)
        self.run_nmap(
            ["-sU", "--top-ports", "100", "-T4", "-Pn", self.target],
            "udp_top100",
            "Top 100 UDP ports"
        )
        
        # 6. VULNERABILITY SCAN
        self.run_nmap(
            ["-sV", "--script=vuln,exploit", "-T4", "-Pn", self.target],
            "vulnerability_scan",
            "Service version + vuln/exploit scripts"
        )
        
        # 7. WEB ENUMERATION (if HTTP found)
        self.run_nmap(
            ["-sV", "--script=http-enum,http-vuln*", "-p80,443,8080", "-T4", self.target],
            "web_enum",
            "Web directory enumeration + vulns"
        )
        
        self.generate_summary()
    
    def generate_summary(self):
        """Create executive summary"""
        summary = f"""
# 🔥 NMAP RECON SUMMARY - {self.timestamp}
Target: {self.target}
Output Directory: {self.output_dir}

## Key Files Generated:
- host_discovery_*.nmap → LIVE HOSTS
- aggressive_full_*.nmap → OS/SERVICES/SCRIPTS
- vulnerability_scan_*.nmap → EXPLOITABLE SERVICES
- udp_top100_*.nmap → UDP FINDINGS
- web_enum_*.nmap → WEB VULNS

## QUICK NEXT STEPS:
1. cat {self.output_dir}/host_discovery_*.nmap.grep | grep open
2. grep -i "vuln\|exploit" {self.output_dir}/vulnerability_scan_*.nmap.nmap
3. nmap -sC -sV -p- <TOP_HOST>  (deep dive top targets)

## VISUALIZE:
xsltproc {self.output_dir}/aggressive_full_*.xml -o recon.html
firefox recon.html
        """
        
        with open(self.output_dir / f"EXECUTIVE_SUMMARY_{self.timestamp}.txt", "w") as f:
            f.write(summary)
        
        print(f"\n📋 SUMMARY: {self.output_dir}/EXECUTIVE_SUMMARY_{self.timestamp}.txt")
        print("🎨 Zenmap: sudo zenmap (GUI visualization)")

def main():
    parser = argparse.ArgumentParser(description="🚀 Advanced Nmap Network Recon Suite")
    parser.add_argument("target", nargs="?", default="auto", 
                       help="IP/range (192.168.1.0/24) or 'auto'")
    parser.add_argument("-o", "--output", default="nmap_recon",
                       help="Output directory")
    parser.add_argument("--quick", action="store_true",
                       help="Quick scan only (top ports)")
    
    args = parser.parse_args()
    
    # Root check
    if os.geteuid() != 0:
        print("⚠️  Run as root for full capabilities: sudo python3 nmap_suite.py")
    
    scanner = AdvancedNmapScanner(args.target, args.output)
    
    if args.quick:
        print("⚡ QUICK MODE")
        scanner.run_nmap(["-F", "-T4", "-A", args.target], "quick_scan", "Fast top-100 + OS")
    else:
        scanner.full_recon()

if __name__ == "__main__":
    main()