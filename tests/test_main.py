import sys
import unittest
from pathlib import Path

from scapy.all import IP, TCP, UDP, Ether

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from scapy_packet_analyser.main import should_capture_packet, summarize_packet


class PacketAnalyzerTests(unittest.TestCase):
    def test_tcp_packet_is_captured_when_protocol_is_tcp(self):
        packet = Ether()/IP()/TCP(dport=80)
        self.assertTrue(should_capture_packet(packet, ["tcp"]))

    def test_udp_packet_is_not_captured_when_protocol_is_tcp(self):
        packet = Ether()/IP()/UDP(dport=53)
        self.assertFalse(should_capture_packet(packet, ["tcp"]))

    def test_summarize_packet_includes_protocol_and_ports(self):
        packet = Ether()/IP(src="192.168.0.10", dst="8.8.8.8")/TCP(sport=5000, dport=80)
        summary = summarize_packet(packet)
        self.assertIn("TCP", summary)
        self.assertIn("5000", summary)
        self.assertIn("80", summary)


if __name__ == "__main__":
    unittest.main()
