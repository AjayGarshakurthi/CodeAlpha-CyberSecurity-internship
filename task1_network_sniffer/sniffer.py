"""
Basic Network Sniffer
CodeAlpha Cybersecurity Internship - Task 1

Captures and analyzes network packets using scapy (primary) or raw sockets (fallback).
Displays source/destination IPs, protocols, ports, and payload data.
"""

import sys
import datetime
import argparse

# ── Try scapy first, fall back to raw socket ──────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import socket
import struct


# ── Colour helpers ────────────────────────────────────────────────────────────
class Color:
    RESET   = "\033[0m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"

def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Color.RESET}"


# ── Protocol map for raw-socket mode ─────────────────────────────────────────
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 89: "OSPF"}


# ═════════════════════════════════════════════════════════════════════════════
#  SCAPY-BASED SNIFFER
# ═════════════════════════════════════════════════════════════════════════════

class ScapySniffer:
    """Full-featured sniffer powered by Scapy."""

    def __init__(self, interface: str = None, packet_count: int = 0,
                 bpf_filter: str = "", verbose: bool = True,
                 log_file: str = None):
        self.interface   = interface
        self.packet_count = packet_count
        self.bpf_filter  = bpf_filter
        self.verbose     = verbose
        self.log_file    = log_file
        self.stats       = {"total": 0, "TCP": 0, "UDP": 0,
                            "ICMP": 0, "ARP": 0, "Other": 0}
        self._log_handle = open(log_file, "w") if log_file else None

    # ── helpers ───────────────────────────────────────────────────────────────
    def _log(self, line: str):
        if self._log_handle:
            self._log_handle.write(line + "\n")
            self._log_handle.flush()

    def _separator(self, char: str = "─", width: int = 70) -> str:
        return colorize(char * width, Color.BLUE)

    def _timestamp(self) -> str:
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _safe_payload(self, data: bytes, max_bytes: int = 64) -> str:
        """Return a readable hex + ASCII dump of raw bytes."""
        data = data[:max_bytes]
        hex_part   = " ".join(f"{b:02x}" for b in data)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return f"{hex_part}  |  {ascii_part}"

    # ── per-protocol handlers ─────────────────────────────────────────────────
    def _handle_tcp(self, pkt):
        self.stats["TCP"] += 1
        flags = pkt[TCP].flags
        flag_str = ""
        flag_map = {"S": "SYN", "A": "ACK", "F": "FIN",
                    "R": "RST", "P": "PSH", "U": "URG"}
        for f, name in flag_map.items():
            if f in str(flags):
                flag_str += f"{name} "

        info = (
            f"  {colorize('Protocol :', Color.CYAN)} TCP\n"
            f"  {colorize('Src      :', Color.GREEN)} {pkt[IP].src}:{pkt[TCP].sport}\n"
            f"  {colorize('Dst      :', Color.RED  )} {pkt[IP].dst}:{pkt[TCP].dport}\n"
            f"  {colorize('Flags    :', Color.YELLOW)} {flag_str.strip()}\n"
            f"  {colorize('Seq/Ack  :', Color.WHITE)} {pkt[TCP].seq} / {pkt[TCP].ack}\n"
            f"  {colorize('Win Size :', Color.WHITE)} {pkt[TCP].window}"
        )
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            info += f"\n  {colorize('Payload  :', Color.MAGENTA)} {self._safe_payload(payload)}"
        return info

    def _handle_udp(self, pkt):
        self.stats["UDP"] += 1
        info = (
            f"  {colorize('Protocol :', Color.CYAN)} UDP\n"
            f"  {colorize('Src      :', Color.GREEN)} {pkt[IP].src}:{pkt[UDP].sport}\n"
            f"  {colorize('Dst      :', Color.RED  )} {pkt[IP].dst}:{pkt[UDP].dport}\n"
            f"  {colorize('Length   :', Color.WHITE)} {pkt[UDP].len}"
        )
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qdcount > 0:
                qname = dns.qd.qname.decode(errors="replace") if dns.qd else "?"
                info += f"\n  {colorize('DNS Query:', Color.YELLOW)} {qname}"
            elif dns.qr == 1 and dns.ancount > 0:
                info += f"\n  {colorize('DNS Reply:', Color.YELLOW)} {dns.ancount} answer(s)"
        elif pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            info += f"\n  {colorize('Payload  :', Color.MAGENTA)} {self._safe_payload(payload)}"
        return info

    def _handle_icmp(self, pkt):
        self.stats["ICMP"] += 1
        icmp_types = {0: "Echo Reply", 3: "Dest Unreachable",
                      8: "Echo Request", 11: "Time Exceeded"}
        t = icmp_types.get(pkt[ICMP].type, f"Type {pkt[ICMP].type}")
        return (
            f"  {colorize('Protocol :', Color.CYAN)} ICMP\n"
            f"  {colorize('Src      :', Color.GREEN)} {pkt[IP].src}\n"
            f"  {colorize('Dst      :', Color.RED  )} {pkt[IP].dst}\n"
            f"  {colorize('Type     :', Color.YELLOW)} {t} (code {pkt[ICMP].code})"
        )

    def _handle_arp(self, pkt):
        self.stats["ARP"] += 1
        op = "Request" if pkt[ARP].op == 1 else "Reply"
        return (
            f"  {colorize('Protocol :', Color.CYAN)} ARP {op}\n"
            f"  {colorize('Src IP   :', Color.GREEN)} {pkt[ARP].psrc}  "
            f"({colorize(pkt[ARP].hwsrc, Color.WHITE)})\n"
            f"  {colorize('Dst IP   :', Color.RED  )} {pkt[ARP].pdst}  "
            f"({colorize(pkt[ARP].hwdst, Color.WHITE)})"
        )

    # ── main callback ─────────────────────────────────────────────────────────
    def process_packet(self, pkt):
        self.stats["total"] += 1
        ts  = self._timestamp()
        num = self.stats["total"]

        header = colorize(f"[#{num:04d}] {ts}", Color.BOLD)
        print(f"\n{self._separator()}")
        print(header)

        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            print(f"  {colorize('Ethernet :', Color.WHITE)} "
                  f"{eth.src} → {eth.dst}  "
                  f"(type 0x{eth.type:04x})")

        if pkt.haslayer(IP):
            ip = pkt[IP]
            ttl_color = Color.GREEN if ip.ttl > 64 else Color.YELLOW
            print(f"  {colorize('IP TTL   :', Color.WHITE)} "
                  f"{colorize(str(ip.ttl), ttl_color)}  "
                  f"len={ip.len}  id=0x{ip.id:04x}")

            if pkt.haslayer(TCP):
                detail = self._handle_tcp(pkt)
            elif pkt.haslayer(UDP):
                detail = self._handle_udp(pkt)
            elif pkt.haslayer(ICMP):
                detail = self._handle_icmp(pkt)
            else:
                self.stats["Other"] += 1
                detail = f"  {colorize('Protocol :', Color.CYAN)} Other (proto={ip.proto})"

        elif pkt.haslayer(ARP):
            detail = self._handle_arp(pkt)
        else:
            self.stats["Other"] += 1
            detail = f"  {colorize('Layer    :', Color.CYAN)} Non-IP / Unknown"

        print(detail)
        self._log(f"[#{num:04d}] {ts}\n{detail}\n")

    # ── start / stop ──────────────────────────────────────────────────────────
    def start(self):
        banner = f"""
{colorize('╔══════════════════════════════════════════════════╗', Color.CYAN)}
{colorize('║        NETWORK PACKET SNIFFER  (Scapy)           ║', Color.CYAN)}
{colorize('║        CodeAlpha Cybersecurity - Task 1           ║', Color.CYAN)}
{colorize('╚══════════════════════════════════════════════════╝', Color.CYAN)}
  Interface : {colorize(self.interface or 'default', Color.GREEN)}
  Filter    : {colorize(self.bpf_filter or 'none', Color.YELLOW)}
  Count     : {colorize(str(self.packet_count) if self.packet_count else 'unlimited', Color.WHITE)}
  Log file  : {colorize(self.log_file or 'none', Color.WHITE)}
  Press Ctrl+C to stop.
"""
        print(banner)
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self.process_packet,
                count=self.packet_count,
                store=False,
            )
        except KeyboardInterrupt:
            pass
        finally:
            self._print_stats()
            if self._log_handle:
                self._log_handle.close()

    def _print_stats(self):
        print(f"\n{self._separator('═')}")
        print(colorize("  CAPTURE SUMMARY", Color.BOLD))
        print(self._separator('═'))
        for k, v in self.stats.items():
            bar = colorize("█" * min(v, 40), Color.CYAN)
            print(f"  {k:<8}: {v:>5}  {bar}")
        print(self._separator('═'))


# ═════════════════════════════════════════════════════════════════════════════
#  RAW-SOCKET FALLBACK SNIFFER  (Linux/macOS only, no scapy needed)
# ═════════════════════════════════════════════════════════════════════════════

class RawSocketSniffer:
    """Minimal sniffer using raw sockets — works without scapy."""

    def __init__(self, packet_count: int = 0):
        self.packet_count = packet_count
        self.count = 0

    def _parse_ip_header(self, data: bytes):
        iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
        version_ihl = iph[0]
        ihl = (version_ihl & 0xF) * 4
        ttl, proto = iph[5], iph[6]
        src = socket.inet_ntoa(iph[8])
        dst = socket.inet_ntoa(iph[9])
        return ihl, ttl, proto, src, dst

    def _parse_tcp(self, data: bytes):
        tcph = struct.unpack("!HHLLBBHHH", data[:20])
        sport, dport = tcph[0], tcph[1]
        flags = tcph[5]
        flag_names = []
        for bit, name in [(0x02,"SYN"),(0x10,"ACK"),(0x01,"FIN"),
                          (0x04,"RST"),(0x08,"PSH"),(0x20,"URG")]:
            if flags & bit:
                flag_names.append(name)
        offset = ((tcph[4] >> 4) & 0xF) * 4
        return sport, dport, " ".join(flag_names), data[offset:]

    def _parse_udp(self, data: bytes):
        udph = struct.unpack("!HHHH", data[:8])
        return udph[0], udph[1], udph[2]

    def start(self):
        print(colorize("\n[RawSocket Sniffer] Starting — Ctrl+C to stop\n", Color.CYAN))
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        except AttributeError:
            print(colorize("[!] AF_PACKET not available on this OS. "
                           "Please install scapy: pip install scapy", Color.RED))
            sys.exit(1)
        except PermissionError:
            print(colorize("[!] Root/admin privileges required.", Color.RED))
            sys.exit(1)

        try:
            while True:
                raw, _ = s.recvfrom(65535)
                eth_payload = raw[14:]          # skip 14-byte Ethernet header
                if len(eth_payload) < 20:
                    continue
                ihl, ttl, proto, src, dst = self._parse_ip_header(eth_payload)
                transport = eth_payload[ihl:]
                self.count += 1
                ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                proto_name = PROTO_MAP.get(proto, f"PROTO-{proto}")

                print(f"\n{colorize('─'*60, Color.BLUE)}")
                print(f"  {colorize(f'[#{self.count:04d}] {ts}', Color.BOLD)}")
                print(f"  {colorize('Src:', Color.GREEN)} {src}  "
                      f"{colorize('Dst:', Color.RED)} {dst}  "
                      f"{colorize('TTL:', Color.WHITE)} {ttl}  "
                      f"{colorize('Proto:', Color.CYAN)} {proto_name}")

                if proto == 6 and len(transport) >= 20:   # TCP
                    sp, dp, flags, payload = self._parse_tcp(transport)
                    print(f"  {colorize('Ports:', Color.YELLOW)} {sp} → {dp}  "
                          f"{colorize('Flags:', Color.MAGENTA)} {flags}")
                    if payload:
                        snippet = payload[:32]
                        ascii_s = "".join(chr(b) if 32<=b<127 else "." for b in snippet)
                        print(f"  {colorize('Payload:', Color.WHITE)} {ascii_s}")

                elif proto == 17 and len(transport) >= 8:  # UDP
                    sp, dp, length = self._parse_udp(transport)
                    print(f"  {colorize('Ports:', Color.YELLOW)} {sp} → {dp}  "
                          f"{colorize('Len:', Color.WHITE)} {length}")

                if self.packet_count and self.count >= self.packet_count:
                    break
        except KeyboardInterrupt:
            print(colorize(f"\n[*] Captured {self.count} packets.", Color.GREEN))
        finally:
            s.close()


# ═════════════════════════════════════════════════════════════════════════════
#  CLI
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer — CodeAlpha Task 1",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface (e.g. eth0, wlan0). Default: auto")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter string (scapy mode only)\n"
                             "Examples: 'tcp', 'udp port 53', 'host 8.8.8.8'")
    parser.add_argument("-l", "--log", default=None,
                        help="Save output to a log file")
    parser.add_argument("--raw", action="store_true",
                        help="Force raw-socket mode (no scapy)")
    args = parser.parse_args()

    if args.raw or not SCAPY_AVAILABLE:
        if not SCAPY_AVAILABLE:
            print(colorize("[!] scapy not found — falling back to raw socket mode.", Color.YELLOW))
            print(colorize("    Install scapy for full features: pip install scapy\n", Color.YELLOW))
        RawSocketSniffer(packet_count=args.count).start()
    else:
        ScapySniffer(
            interface=args.interface,
            packet_count=args.count,
            bpf_filter=args.filter,
            log_file=args.log,
        ).start()


if __name__ == "__main__":
    main()
