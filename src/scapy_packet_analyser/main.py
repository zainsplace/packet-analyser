import argparse
from collections import Counter

from scapy.all import TCP, UDP, sniff


def summarize_packet(packet):
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        summary = f"IP {ip_layer.src} -> {ip_layer.dst}"

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            summary += f" TCP {tcp_layer.sport} -> {tcp_layer.dport}"
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            summary += f" UDP {udp_layer.sport} -> {udp_layer.dport}"

        return summary

    return packet.summary()


def should_capture_packet(packet, protocols):
    normalized = {protocol.lower() for protocol in protocols}
    if not normalized:
        return True

    if "tcp" in normalized and packet.haslayer(TCP):
        return True
    if "udp" in normalized and packet.haslayer(UDP):
        return True
    if "ip" in normalized and packet.haslayer("IP"):
        return True
    if "arp" in normalized and packet.haslayer("ARP"):
        return True

    return False


def live_stats(packet, stats):
    stats["total"] += 1
    if packet.haslayer(TCP):
        stats["tcp"] += 1
    if packet.haslayer(UDP):
        stats["udp"] += 1
    if packet.haslayer("IP"):
        stats["ip"] += 1


def main():
    parser = argparse.ArgumentParser(description="Scapy packet analyser")
    parser.add_argument("--count", type=int, default=10, help="Number of packets to capture")
    parser.add_argument("--iface", default=None, help="Network interface to sniff on")
    parser.add_argument(
        "--protocol",
        action="append",
        choices=["tcp", "udp", "ip", "arp"],
        help="Protocol filter; may be supplied multiple times",
    )
    args = parser.parse_args()

    print(f"Capturing {args.count} packets...")
    stats = Counter(total=0, tcp=0, udp=0, ip=0)

    def packet_handler(packet):
        if not should_capture_packet(packet, args.protocol or []):
            return

        live_stats(packet, stats)
        print(summarize_packet(packet))
        print(f"Stats: total={stats['total']} tcp={stats['tcp']} udp={stats['udp']} ip={stats['ip']}")

    sniff(count=args.count, iface=args.iface, store=False, prn=packet_handler)

    print("Final stats:")
    print(f"total={stats['total']} tcp={stats['tcp']} udp={stats['udp']} ip={stats['ip']}")


if __name__ == "__main__":
    main()
