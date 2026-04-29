import socket
import struct
import textwrap
import sys
import time

# -------------------------------------------------------------------------
# Constants & Colors for Terminal Output
# -------------------------------------------------------------------------
ETH_P_IPV4 = 0x0800
ETH_P_ARP  = 0x0806
ETH_P_IPV6 = 0x86DD

class Colors:
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Map common port numbers to human-readable service names
COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3389: 'RDP',
    5353: 'mDNS'
}

# -------------------------------------------------------------------------
# Formatting Helpers
# -------------------------------------------------------------------------

def get_mac_addr(bytes_addr):
    """Format MAC address to AA:BB:CC:DD:EE:FF"""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def get_ip_str(addr, is_ipv6=False):
    """Format IPv4 or IPv6 address"""
    if is_ipv6:
        return socket.inet_ntop(socket.AF_INET6, addr)
    return '.'.join(map(str, addr))

def get_service_name(port):
    """Return the service name for a port, or just the port number if unknown"""
    return COMMON_PORTS.get(port, str(port))

def hexdump(data, max_lines=10, prefix_indent="    "):
    """
    Creates a Wireshark-style hexdump.
    Shows offset, hex bytes, and printable ASCII.
    """
    if not data:
        return f"{prefix_indent}(Empty Payload)"
    
    result = []
    length = 16 # Bytes per line
    for i in range(0, len(data), length):
        if i // length >= max_lines:
            result.append(f"{prefix_indent}... (payload truncated for display) ...")
            break
            
        chunk = data[i:i+length]
        # Hex representation
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        # ASCII representation (replace non-printable chars with '.')
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        
        # Format: Offset   Hex Block         ASCII
        result.append(f"{prefix_indent}{i:04x}   {hex_str:<{length*3}}   {ascii_str}")
        
    return '\n'.join(result)

def extract_http(data):
    """Attempts to decode payload as HTTP text if it looks like a request/response"""
    try:
        decoded = data.decode('utf-8')
        if "HTTP/" in decoded or "GET " in decoded or "POST " in decoded:
            lines = decoded.split('\r\n')
            # Return the first few lines of the HTTP header
            return '\n'.join([f"        {line}" for line in lines[:5] if line])
    except Exception:
        pass
    return None

# -------------------------------------------------------------------------
# Packet Parsing Functions
# -------------------------------------------------------------------------

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), proto, data[14:]

def arp_packet(data):
    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack('! H H B B H', data[:8])
    if hw_type == 1 and proto_type == ETH_P_IPV4:
        sender_mac, sender_ip, target_mac, target_ip = struct.unpack('! 6s 4s 6s 4s', data[8:28])
        op_str = "Request" if opcode == 1 else "Reply" if opcode == 2 else f"Opcode {opcode}"
        return op_str, get_mac_addr(sender_mac), get_ip_str(sender_ip), get_mac_addr(target_mac), get_ip_str(target_ip), data[28:]
    return "Unknown", None, None, None, None, data[8:]

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, get_ip_str(src), get_ip_str(target), data[header_length:]

def ipv6_packet(data):
    # IPv6 header is 40 bytes. Unpack the Source and Destination IPs
    _, next_header, hop_limit, src, target = struct.unpack('! 4s B B 16s 16s', data[:40])
    return next_header, hop_limit, get_ip_str(src, True), get_ip_str(target, True), data[40:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, ack, offset_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_flags >> 12) * 4
    flags = {
        'URG': (offset_flags & 32) >> 5, 'ACK': (offset_flags & 16) >> 4,
        'PSH': (offset_flags & 8) >> 3,  'RST': (offset_flags & 4) >> 2,
        'SYN': (offset_flags & 2) >> 1,  'FIN': offset_flags & 1
    }
    # Create a nice string of active flags
    active_flags = [name for name, active in flags.items() if active]
    flag_str = ",".join(active_flags) if active_flags else "None"
    
    return src_port, dest_port, sequence, ack, flag_str, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# -------------------------------------------------------------------------
# Main Execution Loop
# -------------------------------------------------------------------------

def main():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print(f"{Colors.BOLD}{Colors.GREEN}[*] Advanced Sniffer started successfully. Listening for traffic...{Colors.END}\n")
    except PermissionError:
        print(f"{Colors.RED}[!] Permission Denied. Run with sudo: sudo python3 advanced_sniffer.py{Colors.END}")
        sys.exit(1)
    except AttributeError:
        print(f"{Colors.RED}[!] OS Compatibility Error. This raw socket script requires Linux.{Colors.END}")
        sys.exit(1)

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            
            timestamp = time.strftime('%H:%M:%S')

            # --- IPv4 Traffic ---
            if eth_proto == ETH_P_IPV4:
                version, hl, ttl, proto, src_ip, tgt_ip, data = ipv4_packet(data)
                
                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print(f"{Colors.YELLOW}[{timestamp}] ICMP | {src_ip} -> {tgt_ip} | Type: {icmp_type} Code: {code}{Colors.END}")
                    print(f"    MAC: {src_mac} -> {dest_mac}")
                    if icmp_type == 3 and code == 1:
                        print(f"    {Colors.RED}Message: Destination Host Unreachable{Colors.END}")
                    elif icmp_type == 8:
                        print("    Message: Echo Request (Ping)")
                    elif icmp_type == 0:
                        print("    Message: Echo Reply (Pong)")
                    print("    Payload:")
                    print(hexdump(data))

                # TCP
                elif proto == 6:
                    src_port, dest_port, seq, ack, flags, data = tcp_segment(data)
                    srv_src, srv_dst = get_service_name(src_port), get_service_name(dest_port)
                    print(f"{Colors.GREEN}[{timestamp}] TCP  | {src_ip}:{srv_src} -> {tgt_ip}:{srv_dst} | Flags: [{flags}]{Colors.END}")
                    print(f"    MAC: {src_mac} -> {dest_mac}")
                    
                    if len(data) > 0:
                        http_data = extract_http(data)
                        if http_data:
                            print(f"    {Colors.CYAN}--- HTTP Text Detected ---{Colors.END}\n{http_data}")
                        else:
                            print("    Payload Hexdump:")
                            print(hexdump(data))

                # UDP
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    srv_src, srv_dst = get_service_name(src_port), get_service_name(dest_port)
                    print(f"{Colors.BLUE}[{timestamp}] UDP  | {src_ip}:{srv_src} -> {tgt_ip}:{srv_dst} | Len: {length}{Colors.END}")
                    print(f"    MAC: {src_mac} -> {dest_mac}")
                    if len(data) > 0:
                        print("    Payload Hexdump:")
                        print(hexdump(data))

            # --- IPv6 Traffic ---
            elif eth_proto == ETH_P_IPV6:
                next_header, hop_limit, src_ip, tgt_ip, data = ipv6_packet(data)
                print(f"{Colors.MAGENTA}[{timestamp}] IPv6 | {src_ip} -> {tgt_ip} | Protocol: {next_header}{Colors.END}")
                print(f"    MAC: {src_mac} -> {dest_mac}")
                print(hexdump(data, max_lines=3)) # Show just a little bit of IPv6 payload

            # --- ARP Traffic ---
            elif eth_proto == ETH_P_ARP:
                op, snd_mac, snd_ip, tgt_mac, tgt_ip, data = arp_packet(data)
                print(f"{Colors.CYAN}[{timestamp}] ARP  | Operation: {op}{Colors.END}")
                if snd_mac:
                    if op == "Request":
                        print(f"    Question: Who has {tgt_ip}? Tell {snd_ip} ({snd_mac})")
                    else:
                        print(f"    Answer: {snd_ip} is at MAC {snd_mac}")
            
            # Print a neat divider between packets
            print("-" * 75)

    except KeyboardInterrupt:
        print(f"\n{Colors.BOLD}{Colors.RED}[*] Sniffer stopped by user.{Colors.END}")
        sys.exit(0)

if __name__ == '__main__':
    main()