import os
import tempfile
import time
import unittest

from sentinel.collectors.packet import match_process
from sentinel.storage import Storage


class InvestigatorTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.storage = Storage(self.path)

    def tearDown(self):
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def test_flow_aggregation(self):
        flow = {
            "timestamp": time.time(),
            "process": "browser.exe",
            "pid": 10,
            "proto": "tcp",
            "direction": "outbound",
            "local_ip": "192.168.1.2",
            "local_port": 50000,
            "remote_ip": "8.8.8.8",
            "remote_port": 443,
            "length": 100,
        }
        self.assertTrue(self.storage.record_flow(flow))
        flow["length"] = 50
        self.assertFalse(self.storage.record_flow(flow))
        row = self.storage.flows(1)[0]
        self.assertEqual(row["packets"], 2)
        self.assertEqual(row["bytes"], 150)

    def test_correlates_medium_anomaly_and_flow(self):
        self.storage.add_event(
            "flow",
            "info",
            "New outbound flow: strange.exe",
            "host -> 8.8.8.8:443",
            process="strange.exe",
            remote_ip="8.8.8.8",
        )
        self.storage.add_alert(
            "medium",
            "anomaly_new_process",
            "New network-active process: strange.exe",
            "First post-baseline external connection",
            process="strange.exe",
            remote_ip="8.8.8.8",
        )
        changed = self.storage.correlate_incidents(window_seconds=120, min_score=30)
        self.assertTrue(changed)
        incidents = self.storage.incidents(status="open")
        self.assertEqual(len(incidents), 1)
        self.assertGreaterEqual(incidents[0]["event_count"], 2)
        events = self.storage.incident_events(incidents[0]["id"])
        self.assertEqual(len(events), 2)

    def test_match_process(self):
        flow = {
            "src_ip": "192.168.1.2",
            "src_port": 50000,
            "dst_ip": "1.1.1.1",
            "dst_port": 443,
            "proto": "tcp",
        }
        connections = [{
            "proto": "tcp",
            "local": {"ip": "192.168.1.2", "port": 50000},
            "remote": {"ip": "1.1.1.1", "port": 443},
            "process": "browser.exe",
            "pid": 123,
        }]
        self.assertEqual(match_process(flow, connections), ("browser.exe", 123))


if __name__ == "__main__":
    unittest.main()
