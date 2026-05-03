"""
Basic Network Sniffer
Captures and analyzes network packets using scapy and socket.
Usage:
    sudo python scapusc.py              # Sniff all traffic (default 20 packets)
    sudo python network_sniffer.py -c 50        # Capture 50 packets
    sudo python network_sniffer.py -i eth0      # Specify interface
    sudo python network_sniffer.py --filter tcp # BPF filter (e.g. tcp, udp, icmp)
    sudo python network_sniffer.py --socket     # Use raw socket instead of scapy
"""

import argparse
import socket
import struct
import textwrap
import sys
from datetime import datetime

# ── Optional scapy import ────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ── Colour helpers (ANSI) ─────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
GREY   = "\033[90m"

PROTO_COLOR = {
    "TCP":  GREEN,
    "UDP":  CYAN,
    "ICMP": YELLOW,
    "DNS":  BLUE,
    "OTHER": GREY,
}

DIVIDER = f"{GREY}{'─' * 70}{RESET}"
packet_count = 0


# ═══════════════════════════════════════════════════════════════════════════════
# SCAPY-BASED SNIFFER
# ═══════════════════════════════════════════════════════════════════════════════

def format_payload(raw_bytes: bytes, width: int = 60) -> str:
    """Return a compact hex + printable-ASCII dump."""
    lines = []
    for i in range(0, len(raw_bytes), 16):
        chunk = raw_bytes[i:i + 16]
        hex_part  = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {GREY}{i:04x}  {hex_part:<48}  {ascii_part}{RESET}")
    return "\n".join(lines)


def scapy_callback(pkt):
    global packet_count
    if not pkt.haslayer(IP):
        return

    packet_count += 1
    ip   = pkt[IP]
    ts   = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    proto_name = "OTHER"

    print(DIVIDER)
    print(f"{BOLD}[#{packet_count}]  {ts}{RESET}")
    print(f"  {BOLD}IP{RESET}    {CYAN}{ip.src}{RESET}  →  {CYAN}{ip.dst}{RESET}   "
          f"TTL={ip.ttl}  Len={ip.len}")

    # ── TCP ──────────────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        proto_name = "TCP"
        tcp = pkt[TCP]
        flags = tcp.sprintf("%flags%")
        color = PROTO_COLOR["TCP"]
        print(f"  {color}{BOLD}TCP{RESET}   "
              f"sport={tcp.sport}  dport={tcp.dport}  "
              f"flags={flags}  seq={tcp.seq}  ack={tcp.ack}")

    # ── UDP ──────────────────────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        proto_name = "UDP"
        udp = pkt[UDP]
        color = PROTO_COLOR["UDP"]
        print(f"  {color}{BOLD}UDP{RESET}   sport={udp.sport}  dport={udp.dport}  len={udp.len}")

        if pkt.haslayer(DNS):
            proto_name = "DNS"
            dns = pkt[DNS]
            if dns.qd:
                qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                print(f"  {BLUE}{BOLD}DNS{RESET}   query={qname}")

    # ── ICMP ─────────────────────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        proto_name = "ICMP"
        icmp = pkt[ICMP]
        type_map = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request",
                    11: "Time Exceeded"}
        type_str = type_map.get(icmp.type, f"type={icmp.type}")
        color = PROTO_COLOR["ICMP"]
        print(f"  {color}{BOLD}ICMP{RESET}  {type_str}  code={icmp.code}")

    # ── Payload preview ───────────────────────────────────────────────────────
    if pkt.haslayer(Raw):
        raw = bytes(pkt[Raw])
        preview_len = min(len(raw), 64)
        print(f"  {GREY}Payload ({len(raw)} bytes, showing first {preview_len}):{RESET}")
        print(format_payload(raw[:preview_len]))


def run_scapy(interface, count, bpf_filter):
    iface_str = interface if interface else "default"
    filter_str = bpf_filter if bpf_filter else "ip"
    print(f"\n{BOLD}[scapy]{RESET} Sniffing on {CYAN}{iface_str}{RESET}  "
          f"filter={YELLOW}{filter_str}{RESET}  count={count}\n"
          f"Press Ctrl+C to stop.\n")
    kwargs = dict(prn=scapy_callback, count=count, filter=filter_str, store=False)
    if interface:
        kwargs["iface"] = interface
    try:
        sniff(**kwargs)
    except PermissionError:
        print(f"{RED}[!] Permission denied – run with sudo.{RESET}")
        sys.exit(1)
    print(f"\n{DIVIDER}")
    print(f"{BOLD}Capture complete.{RESET}  Total packets analysed: {packet_count}")


# ═══════════════════════════════════════════════════════════════════════════════
# RAW SOCKET FALLBACK (Linux only, requires root)
# ═══════════════════════════════════════════════════════════════════════════════

def parse_ethernet(data):
    dest, src, proto = struct.unpack("! 6s 6s H", data[:14])
    return (
        ":".join(f"{b:02x}" for b in dest),
        ":".join(f"{b:02x}" for b in src),
        socket.htons(proto),
        data[14:],
    )


def parse_ipv4(data):
    ver_ihl = data[0]
    ihl = (ver_ihl & 0xF) * 4
    ttl, proto, src, dst = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    src_ip = socket.inet_ntoa(src)
    dst_ip = socket.inet_ntoa(dst)
    return ttl, proto, src_ip, dst_ip, data[ihl:]


def parse_tcp(data):
    (sport, dport, seq, ack, offset_flags) = struct.unpack("! H H L L H", data[:14])
    offset = (offset_flags >> 12) * 4
    flags  = offset_flags & 0x3F
    flag_str = "".join([
        "U" if flags & 0x20 else ".",
        "A" if flags & 0x10 else ".",
        "P" if flags & 0x08 else ".",
        "R" if flags & 0x04 else ".",
        "S" if flags & 0x02 else ".",
        "F" if flags & 0x01 else ".",
    ])
    return sport, dport, seq, ack, flag_str, data[offset:]


def parse_udp(data):
    sport, dport, length = struct.unpack("! H H H 2x", data[:8])
    return sport, dport, length, data[8:]


def parse_icmp(data):
    icmp_type, code, _ = struct.unpack("! B B H", data[:4])
    return icmp_type, code, data[4:]


PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def run_socket(count):
    print(f"\n{BOLD}[socket]{RESET} Raw socket capture  count={count}\n"
          f"Press Ctrl+C to stop.\n")
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except (AttributeError, OSError) as e:
        print(f"{RED}[!] Raw socket unavailable: {e}{RESET}")
        sys.exit(1)

    captured = 0
    try:
        while captured < count:
            raw_data, _ = conn.recvfrom(65535)
            _eth_dst, _eth_src, eth_proto, ip_data = parse_ethernet(raw_data)
            if eth_proto != 8:   # only IPv4 (0x0800)
                continue

            ttl, proto, src_ip, dst_ip, transport = parse_ipv4(ip_data)
            proto_name = PROTO_NAMES.get(proto, f"PROTO-{proto}")
            captured += 1
            ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            color = PROTO_COLOR.get(proto_name, GREY)

            print(DIVIDER)
            print(f"{BOLD}[#{captured}]  {ts}{RESET}")
            print(f"  {BOLD}IP{RESET}    {CYAN}{src_ip}{RESET}  →  {CYAN}{dst_ip}{RESET}   TTL={ttl}")

            if proto == 6:
                sport, dport, seq, ack, flags, payload = parse_tcp(transport)
                print(f"  {color}{BOLD}TCP{RESET}   sport={sport}  dport={dport}  "
                      f"flags={flags}  seq={seq}  ack={ack}")
                if payload:
                    print(f"  {GREY}Payload ({len(payload)} bytes){RESET}")
                    print(format_payload(payload[:64]))

            elif proto == 17:
                sport, dport, length, payload = parse_udp(transport)
                print(f"  {color}{BOLD}UDP{RESET}   sport={sport}  dport={dport}  len={length}")
                if payload:
                    print(f"  {GREY}Payload ({len(payload)} bytes){RESET}")
                    print(format_payload(payload[:64]))

            elif proto == 1:
                icmp_type, code, _ = parse_icmp(transport)
                type_map = {0: "Echo Reply", 8: "Echo Request",
                            3: "Dest Unreachable", 11: "Time Exceeded"}
                type_str = type_map.get(icmp_type, f"type={icmp_type}")
                print(f"  {color}{BOLD}ICMP{RESET}  {type_str}  code={code}")

    except KeyboardInterrupt:
        pass
    finally:
        conn.close()

    print(f"\n{DIVIDER}")
    print(f"{BOLD}Capture complete.{RESET}  Total packets analysed: {captured}")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer – captures & analyses packets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              sudo python network_sniffer.py
              sudo python network_sniffer.py -c 100 -i eth0 --filter tcp
              sudo python network_sniffer.py --socket
        """)
    )
    parser.add_argument("-c", "--count",  type=int,   default=20,
                        help="Number of packets to capture (default: 20)")
    parser.add_argument("-i", "--iface",  type=str,   default=None,
                        help="Network interface (scapy mode only)")
    parser.add_argument("--filter",       type=str,   default=None,
                        help="BPF filter string e.g. 'tcp', 'udp port 53' (scapy only)")
    parser.add_argument("--socket",       action="store_true",
                        help="Use raw socket backend instead of scapy")
    args = parser.parse_args()

    print(f"\n{BOLD}{'═'*70}")
    print(f"  NETWORK SNIFFER  |  Task 1")
    print(f"{'═'*70}{RESET}")

    if args.socket or not SCAPY_AVAILABLE:
        if not SCAPY_AVAILABLE:
            print(f"{YELLOW}[!] scapy not installed – falling back to raw socket mode.{RESET}")
        run_socket(args.count)
    else:
        run_scapy(args.iface, args.count, args.filter)


if __name__ == "__main__":
    main()
