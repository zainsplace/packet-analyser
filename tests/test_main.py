import sys
import unittest
from pathlib import Path

from scapy.all import ARP, IP, TCP, UDP, Ether

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scapy_packet_analyser.main import (
    format_stats,
    live_stats,
    new_stats,
    should_capture_packet,
    summarize_packet,
)


class FilterTests(unittest.TestCase):
    def test_tcp_packet_is_captured_when_protocol_is_tcp(self):
        packet = Ether()/IP()/TCP(dport=80)
        self.assertTrue(should_capture_packet(packet, ["tcp"]))

    def test_udp_packet_is_not_captured_when_protocol_is_tcp(self):
        packet = Ether()/IP()/UDP(dport=53)
        self.assertFalse(should_capture_packet(packet, ["tcp"]))

    def test_empty_filter_captures_everything(self):
        packet = Ether()/ARP()
        self.assertTrue(should_capture_packet(packet, []))

    def test_arp_filter_captures_arp(self):
        packet = Ether()/ARP()
        self.assertTrue(should_capture_packet(packet, ["arp"]))

    def test_arp_filter_rejects_tcp(self):
        packet = Ether()/IP()/TCP(dport=443)
        self.assertFalse(should_capture_packet(packet, ["arp"]))

    def test_multiple_protocols_capture_either(self):
        tcp_packet = Ether()/IP()/TCP(dport=22)
        arp_packet = Ether()/ARP()
        self.assertTrue(should_capture_packet(tcp_packet, ["tcp", "arp"]))
        self.assertTrue(should_capture_packet(arp_packet, ["tcp", "arp"]))

    def test_filter_is_case_insensitive(self):
        packet = Ether()/IP()/TCP(dport=80)
        self.assertTrue(should_capture_packet(packet, ["TCP"]))

    def test_unknown_protocol_name_matches_nothing(self):
        packet = Ether()/IP()/TCP(dport=80)
        self.assertFalse(should_capture_packet(packet, ["icmp6"]))


class SummaryTests(unittest.TestCase):
    def test_summarize_packet_includes_protocol_and_ports(self):
        packet = Ether()/IP(src="192.168.0.10", dst="8.8.8.8")/TCP(sport=5000, dport=80)
        summary = summarize_packet(packet)
        self.assertIn("TCP", summary)
        self.assertIn("5000", summary)
        self.assertIn("80", summary)

    def test_summarize_packet_includes_udp_ports(self):
        packet = Ether()/IP(src="10.0.0.1", dst="1.1.1.1")/UDP(sport=5353, dport=53)
        summary = summarize_packet(packet)
        self.assertIn("UDP", summary)
        self.assertIn("5353", summary)
        self.assertIn("53", summary)

    def test_summarize_packet_includes_addresses(self):
        packet = Ether()/IP(src="192.168.0.10", dst="8.8.8.8")/TCP()
        summary = summarize_packet(packet)
        self.assertIn("192.168.0.10", summary)
        self.assertIn("8.8.8.8", summary)

    def test_non_ip_packet_falls_back_to_scapy_summary(self):
        packet = Ether()/ARP(pdst="192.168.0.1")
        summary = summarize_packet(packet)
        self.assertIn("ARP", summary)


class StatsTests(unittest.TestCase):
    def test_new_stats_starts_at_zero(self):
        stats = new_stats()
        self.assertEqual(set(stats), {"total", "tcp", "udp", "ip", "arp"})
        self.assertTrue(all(value == 0 for value in stats.values()))

    def test_tcp_packet_increments_tcp_ip_and_total(self):
        stats = new_stats()
        live_stats(Ether()/IP()/TCP(dport=80), stats)
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["tcp"], 1)
        self.assertEqual(stats["ip"], 1)
        self.assertEqual(stats["udp"], 0)
        self.assertEqual(stats["arp"], 0)

    def test_arp_packet_increments_arp_and_total(self):
        stats = new_stats()
        live_stats(Ether()/ARP(), stats)
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["arp"], 1)
        self.assertEqual(stats["ip"], 0)

    def test_format_stats_lists_every_counter(self):
        stats = new_stats()
        live_stats(Ether()/IP()/UDP(dport=53), stats)
        formatted = format_stats(stats)
        self.assertEqual(formatted, "total=1 tcp=0 udp=1 ip=1 arp=0")


if __name__ == "__main__":
    unittest.main()
