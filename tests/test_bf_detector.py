import unittest
from datetime import datetime, timedelta
from detectors.bf_detector import detect_brute_force

class TestBruteForceDetector(unittest.TestCase):
    
    def test_detects_brute_force(self):
        base_time = datetime(2025, 6, 30, 12, 0, 0)
        entries = []
        # 5 failed attempts within 1 minute
        for i in range(5):
            entries.append({
                "ip": "192.168.1.1",
                "timestamp": base_time + timedelta(seconds=i * 10),
                "status": "Failed"
            })

        result = detect_brute_force(entries)
        self.assertIn("192.168.1.1", result)

    def test_no_brute_force_if_spread_out(self):
        base_time = datetime(2025, 6, 30, 12, 0, 0)
        entries = []
        # 5 failed attempts spread over 5 minutes
        for i in range(5):
            entries.append({
                "ip": "192.168.1.2",
                "timestamp": base_time + timedelta(minutes=i),
                "status": "Failed"
            })

        result = detect_brute_force(entries)
        self.assertNotIn("192.168.1.2", result)

if __name__ == '__main__':
    unittest.main()
