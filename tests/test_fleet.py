import os
import tempfile
import unittest

from sentinel.collectors.device_probe import parse_ports
from sentinel.storage import Storage


class FleetTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.storage = Storage(self.path)
        self.storage.upsert_device(
            "192.168.1.20",
            "00:11:22:33:44:55",
            "Ethernet",
            hostname="test-device",
            vendor="Example",
        )

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def test_probe_history_and_service_change(self):
        first = self.storage.record_device_probe(
            {
                "ip": "192.168.1.20",
                "online": True,
                "latency_ms": 3.5,
                "services": [{"proto": "tcp", "port": 80, "service": "HTTP"}],
            }
        )
        self.assertFalse(first["changed"])

        second = self.storage.record_device_probe(
            {
                "ip": "192.168.1.20",
                "online": True,
                "latency_ms": 4.0,
                "services": [
                    {"proto": "tcp", "port": 80, "service": "HTTP"},
                    {"proto": "tcp", "port": 443, "service": "HTTPS"},
                ],
            }
        )
        self.assertTrue(second["changed"])
        self.assertEqual(second["added"][0]["port"], 443)

        profile = self.storage.device_profile("192.168.1.20", online_window=9999)
        self.assertTrue(profile["monitored"])
        self.assertTrue(profile["probe_online"])
        self.assertEqual(profile["open_service_count"], 2)
        self.assertEqual(len(self.storage.device_history("192.168.1.20")), 2)

    def test_offline_transition_and_traffic_aggregation(self):
        self.storage.record_device_probe(
            {"ip": "192.168.1.20", "online": True, "latency_ms": 2.0, "services": []}
        )
        result = self.storage.record_device_probe(
            {"ip": "192.168.1.20", "online": False, "latency_ms": None, "services": []}
        )
        self.assertEqual(result["state_change"], "offline")

        self.storage.record_device_packet("192.168.1.20", "from", 100)
        self.storage.record_device_packet("192.168.1.20", "to", 60)
        traffic = self.storage.device_traffic("192.168.1.20")
        self.assertEqual(traffic["bytes_from"], 100)
        self.assertEqual(traffic["bytes_to"], 60)
        self.assertEqual(traffic["packets_from"], 1)
        self.assertEqual(traffic["packets_to"], 1)

    def test_service_port_parser_is_bounded(self):
        ports = parse_ports("22,443,443,0,70000,nope")
        self.assertEqual(ports, (22, 443))


if __name__ == "__main__":
    unittest.main()
