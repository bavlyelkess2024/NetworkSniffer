#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1
Basic Network Sniffer

A simple, educational packet sniffer built with Scapy. It captures live
network traffic and prints out useful information about each packet:
source/destination IP addresses, the transport-layer protocol, ports
(when applicable), and a preview of the raw payload.

IMPORTANT / LEGAL NOTE:
Only run this tool on networks and devices you own or have explicit
permission to monitor. Capturing traffic on networks you do not control
may be illegal in your jurisdiction. This script is for educational
purposes as part of a cybersecurity internship task.

Usage:
    sudo python3 network_sniffer.py                  # sniff all interfaces
    sudo python3 network_sniffer.py -i eth0           # sniff a specific interface
    sudo python3 network_sniffer.py -c 50             # stop after 50 packets
    sudo python3 network_sniffer.py -f "tcp port 80"  # apply a BPF filter
    sudo python3 network_sniffer.py -o capture.log    # also save output to a log file

Requires root/administrator privileges to open a raw socket, and the
`scapy` library (pip install scapy).
"""

import argparse
import datetime
import sys

try:
    from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw
except ImportError:
    print("[!] Scapy is not installed. Install it with: pip install scapy")
    sys.exit(1)

# Well-known ports we like to label for readability
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-ALT",
}

log_file_handle = None


def log(line: str) -> None:
    """Print a line to stdout and, if enabled, append it to the log file."""
    print(line)
    if log_file_handle:
        log_file_handle.write(line + "\n")
        log_file_handle.flush()


def label_port(port: int) -> str:
    name = COMMON_PORTS.get(port)
    return f"{port} ({name})" if name else str(port)


def describe_payload(packet) -> str:
    """Return a short, safe, printable preview of the raw payload."""
    if Raw not in packet:
        return ""
    raw_bytes = bytes(packet[Raw].load)
    preview = raw_bytes[:64]
    try:
        text = preview.decode("utf-8", errors="replace")
    except Exception:
        text = repr(preview)
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    suffix = "..." if len(raw_bytes) > 64 else ""
    return f'Payload ({len(raw_bytes)} bytes): "{text}{suffix}"'


def handle_packet(packet) -> None:
    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # Determine the network layer (IPv4/IPv6) and addresses
    if IP in packet:
        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        ip_version = "IPv4"
    elif IPv6 in packet:
        src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
        ip_version = "IPv6"
    else:
        # Not an IP packet (e.g. ARP) - show a minimal line and move on
        if Ether in packet:
            log(f"[{timestamp}] Non-IP frame | {packet.summary()}")
        return

    # Determine the transport layer protocol and ports
    if TCP in packet:
        proto = "TCP"
        sport, dport = packet[TCP].sport, packet[TCP].dport
        port_info = f"{label_port(sport)} -> {label_port(dport)}"
        flags = packet[TCP].flags
        extra = f"flags={flags}"
    elif UDP in packet:
        proto = "UDP"
        sport, dport = packet[UDP].sport, packet[UDP].dport
        port_info = f"{label_port(sport)} -> {label_port(dport)}"
        extra = ""
    elif ICMP in packet:
        proto = "ICMP"
        port_info = "-"
        extra = f"type={packet[ICMP].type} code={packet[ICMP].code}"
    else:
        proto = f"OTHER({ip_version})"
        port_info = "-"
        extra = ""

    header_line = f"[{timestamp}] {ip_version} {proto:<12} {src_ip:>15} -> {dst_ip:<15} | Ports: {port_info}"
    if extra:
        header_line += f" | {extra}"
    log(header_line)

    payload_desc = describe_payload(packet)
    if payload_desc:
        log(f"    {payload_desc}")


def main():
    parser = argparse.ArgumentParser(description="Basic educational network sniffer using Scapy")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: all)")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Number of packets to capture (0 = unlimited, stop with Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                         help='BPF filter string, e.g. "tcp port 80" or "udp"')
    parser.add_argument("-o", "--output", help="Optional path to also save output as a log file")
    args = parser.parse_args()

    global log_file_handle
    if args.output:
        log_file_handle = open(args.output, "a", encoding="utf-8")
        log(f"\n=== Capture started {datetime.datetime.now().isoformat()} ===")

    print("=" * 70)
    print(" CodeAlpha Task 1 - Basic Network Sniffer")
    print(f" Interface : {args.interface or 'ALL'}")
    print(f" Filter    : {args.filter or 'none'}")
    print(f" Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("=" * 70)
    print("[*] Note: capturing raw traffic usually requires root/admin privileges.\n")

    try:
        sniff(
            iface=args.interface if args.interface else None,
            filter=args.filter if args.filter else None,
            prn=handle_packet,
            count=args.count if args.count > 0 else 0,
            store=False,
        )
    except PermissionError:
        print("[!] Permission denied. Try running with sudo / as Administrator.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")
    finally:
        if log_file_handle:
            log_file_handle.close()


if __name__ == "__main__":
    main()
