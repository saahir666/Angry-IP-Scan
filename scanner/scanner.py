import socket
import struct
import textwrap
import sys

# -------------------------------------------------------------------------
# Formatting Helpers
# -------------------------------------------------------------------------

# Return properly formatted MAC address (e.g., AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Return properly formatted IPv4 address (e.g., 192.168.1.1)
def ipv4(addr):
    return '.'.join(map(str, addr))

# Multi-line string formatter for cleanly displaying payload data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


# -------------------------------------------------------------------------
# Packet Parsing Functions
# -------------------------------------------------------------------------

# Unpack Ethernet frame (Layer 2)
def ethernet_frame(data):
    # struct.unpack extracts the first 14 bytes:
    # 6 bytes (Destination MAC) + 6 bytes (Source MAC) + 2 bytes (Type/Protocol)
    # ! = network byte order (big-endian), 6s = 6 character string, H = unsigned short (2 bytes)
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    
    # Return destination MAC, source MAC, the protocol, and the remaining payload
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Unpack IPv4 packet (Layer 3)
def ipv4_packet(data):
    # The first byte contains the Version and Header Length
    version_header_length = data[0]
    
    # Bitwise shift right by 4 to get the first 4 bits (Version)
    version = version_header_length >> 4
    
    # Bitwise AND with 15 (00001111) to get the last 4 bits, then multiply by 4 to get bytes
    header_length = (version_header_length & 15) * 4
    
    # Unpack TTL, Protocol, Source IP, and Target IP
    # 8x = 8 pad bytes (skipped), B = unsigned char (1 byte), 2x = 2 pad bytes, 4s = 4 byte string
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Unpack ICMP packet (Layer 4)
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# Unpack TCP segment (Layer 4)
def tcp_segment(data):
    # Unpack Source Port, Destination Port, Sequence, Acknowledgment, and Offset/Flags
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    
    # Extract the header length (offset) by shifting right 12 bits and multiplying by 4
    offset = (offset_reserved_flags >> 12) * 4
    
    # Extract the flags using bitwise AND operations
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# Unpack UDP segment (Layer 4)
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# -------------------------------------------------------------------------
# Main Execution Loop
# -------------------------------------------------------------------------

def main():
    try:
        # Create a raw socket to capture all network traffic (Linux only)
        # AF_PACKET: Operates at the device driver layer (captures Ethernet frames)
        # SOCK_RAW: Raw socket
        # ntohs(3): Captures ALL protocols (0x0003)
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("[*] Sniffer started successfully. Listening for traffic...")
    except PermissionError:
        print("[!] Permission Denied. Please run this script with root privileges (e.g., sudo python3 sniffer.py).")
        sys.exit(1)
    except AttributeError:
        print("[!] Compatibility Error. This specific script uses AF_PACKET and is designed for Linux systems.")
        sys.exit(1)

    try:
        while True:
            # Receive data and the address it came from (buffer size 65535)
            raw_data, addr = conn.recvfrom(65535)
            
            # Parse Layer 2 (Ethernet)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\n' + '='*60)
            print('Ethernet Frame:')
            print(f'  Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')

            # Standard IPv4 Protocol (Protocol 8 in Ethernet header)
            if eth_proto == 8:
                # Parse Layer 3 (IPv4)
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                print(f'  IPv4 Packet:')
                print(f'    Version: {version}, Header Length: {header_length}, TTL: {ttl}')
                print(f'    Protocol: {proto}, Source: {src}, Target: {target}')

                # Parse Layer 4 protocols based on the IPv4 Protocol field
                
                # ICMP (Protocol 1)
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print('    ICMP Packet:')
                    print(f'      Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                    print('      Payload:')
                    print(format_multi_line('        ', data))

                # TCP (Protocol 6)
                elif proto == 6:
                    src_port, dest_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                    print('    TCP Segment:')
                    print(f'      Source Port: {src_port}, Destination Port: {dest_port}')
                    print(f'      Sequence: {seq}, Acknowledgment: {ack}')
                    print('      Flags:')
                    print(f'        URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}')
                    print('      Payload:')
                    print(format_multi_line('        ', data))

                # UDP (Protocol 17)
                elif proto == 17:
                    src_port, dest_port, length, data = udp_segment(data)
                    print('    UDP Segment:')
                    print(f'      Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                    print('      Payload:')
                    print(format_multi_line('        ', data))

                # Other protocols
                else:
                    print('    Other Protocol Payload Data:')
                    print(format_multi_line('      ', data))
            else:
                print('  Non-IPv4 Payload Data:')
                print(format_multi_line('    ', data))

    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")
        sys.exit(0)

if __name__ == '__main__':
    main()