import os
import tempfile
import unittest

from sentinel.intelligence import device_risk, process_communications, process_dns_records
from sentinel.storage import Storage


class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.storage = Storage(self.path)

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def test_device_risk_is_explainable(self):
        self.storage.upsert_device(
            "192.168.1.20",
            "02:11:22:33:44:55",
            "Ethernet",
            hostname=None,
            vendor=None,
        )
        device = self.storage.devices(9999)[0]
        risk = device_risk(device)
        self.assertGreaterEqual(risk["score"], 0)
        self.assertLessEqual(risk["score"], 100)
        self.assertTrue(risk["reasons"])

    def test_baseline_history_records_endpoints_and_dns(self):
        connections = [
            {
                "process": "browser.exe",
                "pid": 123,
                "proto": "tcp",
                "remote": {"ip": "8.8.8.8", "port": 443},
                "local": {"ip": "192.168.1.2", "port": 50123},
                "status": "ESTABLISHED",
            }
        ]
        process_communications(
            self.storage,
            connections,
            baseline_ready=False,
            fanout_threshold=25,
            endpoint_churn_threshold=12,
        )
        process_dns_records(
            self.storage,
            [
                {
                    "domain": "example.com",
                    "record_type": "A",
                    "data": "93.184.216.34",
                    "ttl": 60,
                }
            ],
            baseline_ready=False,
            burst_threshold=25,
        )
        counts = self.storage.baseline_counts()
        self.assertEqual(counts["processes"], 1)
        self.assertEqual(counts["endpoints"], 1)
        self.assertEqual(counts["domains"], 1)


if __name__ == "__main__":
    unittest.main()
