#!/usr/bin/env python3
"""
🚀 ANGRYSCAN v3.0 - ULTIMATE NMAP SUITE
Permission-proof, Kali-optimized, Production-ready
"""

import subprocess
import sys
import os
import argparse
import time
from pathlib import Path
import getpass

class AngryScan:
    def __init__(self, target, output_dir=None):
        self.target = target
        user = getpass.getuser()
        self.output_dir = Path(f"/home/{user}/{output_dir or 'angry_recon'}")
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        # Fix permissions
        os.chmod(str(self.output_dir), 0o755)
        
        print(f"🔥 ANGRYSCAN v3.0 INITIALIZED")
        print(f"🎯 Target: {target}")
        print(f"📁 Output: {self.output_dir}")
    
    def cmd(self, cmd_args, name, timeout=300):
        """Universal command runner - handles sudo + perms"""
        full_cmd = ["sudo", "nmap"] + cmd_args + [
            "-oN", f"{self.output_dir}/{name}_{self.timestamp}.nmap",
            "-oG", f"{self.output_dir}/{name}_{self.timestamp}.gnmap"
        ]
        
        print(f"\n[{name.upper()}] {' '.join(full_cmd[-5:])} {self.target}")
        
        try:
            result = subprocess.run(
                full_cmd, 
                timeout=timeout,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print(f"✅ {name.upper()} OK")
                return True
            else:
                print(f"⚠️  {name.upper()} WARN: {result.stderr[:100]}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"⏰ {name.upper()} TIMEOUT")
            return False
    
    def auto_network(self):
        """Smart network detection"""
        nets = ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]
        try:
            ip_out = subprocess.run(["hostname", "-I"], capture_output=True, text=True)
            for ip in ip_out.stdout.strip().split():
                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                if net.network_address in ipaddress.IPv4Network("192.168.0.0/16"):
                    return str(net)
        except:
            pass
        return nets[0]
    
    def scan_all(self):
        """Execute everything"""
        if self.target == "auto":
            self.target = self.auto_network()
        
        print(f"\n🌐 SCANNING {self.target}")
        
        # CORE SCANS
        self.cmd(["-sn", "-T4"], "HOSTS", 120)           # Live hosts
        self.cmd(["-PR", "-T4"], "ARP", 60)              # Local ARP
        self.cmd(["-sS", "-T4", "-Pn"], "SYN", 180)      # SYN scan
        self.cmd(["-sU", "--top-ports=20", "-T3"], "UDP", 240)  # UDP top20
        self.cmd(["-sV", "--script=vuln", "-T4"], "VULN", 300)  # Vulns
        self.cmd(["-O", "-T4"], "OS", 240)               # OS detect
        
        self.make_summary()
    
    def make_summary(self):
        """Permission-safe summary"""
        summary_path = self.output_dir / f"SUMMARY_{self.timestamp}.txt"
        summary = f"""# ANGRYSCAN RESULTS {self.timestamp}
TARGET: {self.target}
DIR: {self.output_dir}

LIVE HOSTS: cat {self.output_dir}/HOSTS_*.gnmap | grep Status: Up
VULNS: grep -i vuln {self.output_dir}/VULN_*.nmap
SERVICES: grep open {self.output_dir}/SYN_*.gnmap

NEXT: nmap -sC -sV -p- <BEST_HOST>
GUI: zenmap {self.output_dir}/OS_*.gnmap
"""
        
        try:
            with open(summary_path, "w") as f:
                f.write(summary)
            os.chmod(str(summary_path), 0o644)
            print(f"\n📋 SUMMARY: {summary_path}")
        except:
            print(f"\n📋 SUMMARY CONTENT:\n{summary}")

def main():
    parser = argparse.ArgumentParser(description="🔥 ANGRYSCAN - Ultimate Nmap")
    parser.add_argument("target", nargs="?", default="auto")
    parser.add_argument("-o", "--out")
    args = parser.parse_args()
    
    AngryScan(args.target, args.out).scan_all()

if __name__ == "__main__":
    main()
