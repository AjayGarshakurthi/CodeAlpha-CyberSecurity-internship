# Task 1 — Basic Network Sniffer

## Features
- Captures live packets on any interface
- Decodes Ethernet, IP, TCP, UDP, ICMP, ARP, DNS layers
- Shows flags, sequence numbers, window size (TCP)
- Hex + ASCII payload dump
- BPF filter support (e.g. `tcp`, `udp port 53`, `host 8.8.8.8`)
- Colour-coded terminal output
- Optional log file
- Falls back to raw sockets if scapy is not installed

## Setup
```bash
pip install scapy
```

## Usage
```bash
# Capture all traffic (requires root/admin)
sudo python sniffer.py

# Capture 20 TCP packets on eth0
sudo python sniffer.py -i eth0 -c 20 -f "tcp"

# Capture DNS queries and save to log
sudo python sniffer.py -f "udp port 53" -l dns_log.txt

# Raw socket fallback (no scapy)
sudo python sniffer.py --raw
```

## Output Example
```
──────────────────────────────────────────────────────────────────────
[#0001] 2026-05-13 10:22:31.456
  Ethernet : aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66  (type 0x0800)
  IP TTL   : 64  len=60  id=0x1a2b
  Protocol : TCP
  Src      : 192.168.1.5:54321
  Dst      : 93.184.216.34:443
  Flags    : SYN
  Seq/Ack  : 123456789 / 0
  Win Size : 65535
```
