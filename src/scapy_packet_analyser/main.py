import argparse

from scapy.all import TCP, UDP, sniff

PROTOCOL_LAYERS = {"tcp": TCP, "udp": UDP, "ip": "IP", "arp": "ARP"}
STAT_NAMES = ("total", "tcp", "udp", "ip", "arp")


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

    return any(
        packet.haslayer(layer)
        for name, layer in PROTOCOL_LAYERS.items()
        if name in normalized
    )


def new_stats():
    return dict.fromkeys(STAT_NAMES, 0)


def live_stats(packet, stats):
    stats["total"] += 1
    for name, layer in PROTOCOL_LAYERS.items():
        if packet.haslayer(layer):
            stats[name] += 1


def format_stats(stats):
    return " ".join(f"{name}={stats[name]}" for name in STAT_NAMES)


def main():
    parser = argparse.ArgumentParser(description="Scapy packet analyser")
    parser.add_argument("--count", type=int, default=10, help="Number of packets to capture")
    parser.add_argument("--iface", default=None, help="Network interface to sniff on")
    parser.add_argument(
        "--protocol",
        action="append",
        choices=sorted(PROTOCOL_LAYERS),
        help="Protocol filter; may be supplied multiple times",
    )
    args = parser.parse_args()

    print(f"Capturing {args.count} packets...")
    stats = new_stats()

    def packet_handler(packet):
        if not should_capture_packet(packet, args.protocol or []):
            return

        live_stats(packet, stats)
        print(summarize_packet(packet))
        print(f"Stats: {format_stats(stats)}")

    try:
        sniff(count=args.count, iface=args.iface, store=False, prn=packet_handler)
    except PermissionError:
        raise SystemExit(
            "error: packet capture requires elevated privileges; "
            "run as administrator/root"
        )
    except OSError as exc:
        raise SystemExit(f"error: capture failed: {exc}")

    print("Final stats:")
    print(format_stats(stats))


if __name__ == "__main__":
    main()
