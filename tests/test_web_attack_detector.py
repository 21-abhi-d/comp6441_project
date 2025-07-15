import unittest
from detectors.web_attack_detector import is_suspicious

class TestWebAttackDetector(unittest.TestCase):

    def test_sql_injection(self):
        entry = {"path": "/search.php?q=1=1", "agent": "Mozilla/5.0"}
        reason = is_suspicious(entry)
        self.assertEqual(reason, "SQL Injection")

    def test_path_traversal(self):
        entry = {"path": "/../../etc/passwd", "agent": "Mozilla/5.0"}
        reason = is_suspicious(entry)
        self.assertEqual(reason, "Path Traversal")

    def test_suspicious_user_agent(self):
        entry = {"path": "/", "agent": "sqlmap"}
        reason = is_suspicious(entry)
        self.assertEqual(reason, "Suspicious User-Agent")

    def test_sensitive_path(self):
        entry = {"path": "/admin", "agent": "Mozilla/5.0"}
        reason = is_suspicious(entry)
        self.assertEqual(reason, "Access to Sensitive Path")

    def test_clean_entry(self):
        entry = {"path": "/home", "agent": "Mozilla/5.0"}
        reason = is_suspicious(entry)
        self.assertIsNone(reason)

if __name__ == '__main__':
    unittest.main()
