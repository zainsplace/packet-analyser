# Scapy Packet Analyser

A lightweight Python project for capturing and summarizing network traffic with Scapy.

## Features

- Sniff live packets from a chosen interface
- Print concise summaries for IP, TCP, and UDP traffic
- Filter by protocol such as tcp, udp, ip, or arp
- Show live packet counters while capture is running
- Configure packet count and interface from the command line

## Quick start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
python -m scapy_packet_analyser --count 10 --protocol tcp --protocol udp
```

> On Windows, you may need to run the terminal with elevated privileges for packet capture access.
