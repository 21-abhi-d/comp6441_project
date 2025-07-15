import unittest
from access_log_parser import parse_access_log_line

class TestAccessLogParser(unittest.TestCase):

    def test_valid_get_line(self):
        line = '192.168.0.1 - - [30/Jun/2025:10:12:45 +0000] "GET /admin HTTP/1.1" 403 200 "-" "curl/7.80.0"'
        result = parse_access_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["path"], "/admin")
        self.assertEqual(result["status"], "403")

    def test_invalid_line(self):
        line = "garbage log line"
        result = parse_access_log_line(line)
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
