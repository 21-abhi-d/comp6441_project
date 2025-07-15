import unittest
from auth_log_parser import parse_auth_log_line

class TestAuthLogParser(unittest.TestCase):

    def test_valid_failed_line(self):
        line = "Jun 30 10:12:45 myserver sshd[12345]: Failed password for invalid user admin from 192.168.0.10 port 54321 ssh2"
        result = parse_auth_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "Failed")
        self.assertEqual(result["user"], "admin")
        self.assertEqual(result["ip"], "192.168.0.10")

    def test_invalid_line(self):
        line = "This is a random line"
        result = parse_auth_log_line(line)
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
