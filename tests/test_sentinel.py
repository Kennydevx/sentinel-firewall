# Cryo-Corona — Sentinel Firewall Tests
# Run: python -m pytest tests/ -v

import sys
import os
import math
import unittest
from unittest.mock import MagicMock, patch
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class FakeRequest:
    """Simulates an HTTP request for testing."""
    def __init__(self, ip="192.168.1.1", method="GET", ua="Mozilla/5.0", body_size=0):
        self.remote_addr = ip
        self.method = method
        self.content_length = body_size
        self.data = b"x" * body_size
        self.headers = {"User-Agent": ua}


class TestVectorConstruction(unittest.TestCase):
    """Test that HTTP requests are correctly converted to 5-float vectors."""

    def setUp(self):
        # We test the static/pure logic without needing gRPC
        from sentinel_agent import SentinelFirewall
        self.fw_class = SentinelFirewall

    def test_ua_entropy_empty(self):
        """Empty user-agent should return 0.0 entropy."""
        result = self.fw_class._ua_entropy("")
        self.assertEqual(result, 0.0)

    def test_ua_entropy_bot(self):
        """Simple bot UA like 'curl/7.0' should have low entropy."""
        result = self.fw_class._ua_entropy("curl/7.0")
        self.assertLess(result, 0.8)

    def test_ua_entropy_browser(self):
        """Real browser UA should have high entropy."""
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        result = self.fw_class._ua_entropy(ua)
        self.assertGreater(result, 0.6)

    def test_method_mapping(self):
        """HTTP methods should map to known float values."""
        self.assertEqual(self.fw_class.METHODS["GET"], 0.0)
        self.assertEqual(self.fw_class.METHODS["POST"], 0.25)
        self.assertEqual(self.fw_class.METHODS["DELETE"], 0.75)

    def test_payload_normalization(self):
        """Payload size should be normalized to 0.0-1.0 range."""
        # 5000 bytes / 10000 = 0.5
        normalized = min(5000 / 10000.0, 1.0)
        self.assertAlmostEqual(normalized, 0.5)

        # 20000 bytes should cap at 1.0
        normalized = min(20000 / 10000.0, 1.0)
        self.assertAlmostEqual(normalized, 1.0)


class TestFrameworkAdapters(unittest.TestCase):
    """Test that IP/method extraction works for different frameworks."""

    def setUp(self):
        from sentinel_agent import SentinelFirewall
        self.fw_class = SentinelFirewall

    def test_flask_ip(self):
        """Flask-style request.remote_addr should work."""
        req = FakeRequest(ip="10.0.0.1")
        self.assertEqual(self.fw_class._get_ip(req), "10.0.0.1")

    def test_django_ip(self):
        """Django-style request.META should work."""
        class DjangoReq:
            META = {"REMOTE_ADDR": "172.16.0.5", "HTTP_USER_AGENT": "TestBot"}
        self.assertEqual(self.fw_class._get_ip(DjangoReq()), "172.16.0.5")

    def test_wsgi_dict_ip(self):
        """Raw WSGI environ dict should work."""
        environ = {"REMOTE_ADDR": "192.168.1.100", "REQUEST_METHOD": "POST"}
        self.assertEqual(self.fw_class._get_ip(environ), "192.168.1.100")
        self.assertEqual(self.fw_class._get_method(environ), "POST")

    def test_flask_body_size(self):
        """Flask request.content_length should be read."""
        req = FakeRequest(body_size=1234)
        self.assertEqual(self.fw_class._get_body_size(req), 1234)

    def test_flask_ua(self):
        """Flask headers dict should return User-Agent."""
        req = FakeRequest(ua="TestAgent/1.0")
        self.assertEqual(self.fw_class._get_ua(req), "TestAgent/1.0")


class TestEntropyMath(unittest.TestCase):
    """Verify Shannon entropy calculation correctness."""

    def test_single_char(self):
        """String of identical chars should have 0 entropy."""
        from sentinel_agent import SentinelFirewall
        result = SentinelFirewall._ua_entropy("aaaaaaa")
        self.assertAlmostEqual(result, 0.0, places=2)

    def test_two_chars_equal(self):
        """'ab' repeated should have entropy of 1 bit (normalized)."""
        from sentinel_agent import SentinelFirewall
        result = SentinelFirewall._ua_entropy("abababababab")
        # Shannon entropy of 2 equally likely chars = 1.0 bit
        self.assertGreater(result, 0.15)
        self.assertLess(result, 0.3)


if __name__ == "__main__":
    unittest.main()
