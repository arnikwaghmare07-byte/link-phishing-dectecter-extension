"""
Unit Tests for URL Normalization and Checker
"""

import unittest
import sys
import os

# Add backend directory to sys.path so modules can be imported directly
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from url_checker import normalize_url, check_demo_signal, check_multiple_urls, check_url_reputation
from threat_classifier import STATUS_SAFE, STATUS_SUSPICIOUS, STATUS_MALICIOUS, STATUS_UNKNOWN


class TestURLChecker(unittest.TestCase):
    def test_normalize_valid_urls(self):
        url, domain = normalize_url("https://EXAMPLE.com/path?foo=bar#section")
        self.assertEqual(url, "https://example.com/path?foo=bar")
        self.assertEqual(domain, "example.com")

        # Missing scheme defaults to https
        url2, domain2 = normalize_url("google.com/search")
        self.assertEqual(url2, "https://google.com/search")
        self.assertEqual(domain2, "google.com")

    def test_normalize_rejects_invalid_urls(self):
        # JavaScript protocol should be rejected
        url, domain = normalize_url("javascript:alert(1)")
        self.assertIsNone(url)
        self.assertIsNone(domain)

        # Mailto protocol should be rejected
        url2, domain2 = normalize_url("mailto:test@example.com")
        self.assertIsNone(url2)

        # Hash anchors should be rejected
        url3, domain3 = normalize_url("#top-of-page")
        self.assertIsNone(url3)

        # Non-URL strings
        url4, domain4 = normalize_url("just-a-word")
        self.assertIsNone(url4)

    def test_demo_signal_detection(self):
        # Malicious pattern
        sig1 = check_demo_signal("https://malicious-example.test/login", "malicious-example.test")
        self.assertIsNotNone(sig1)
        self.assertEqual(sig1["status"], STATUS_MALICIOUS)

        # Suspicious pattern
        sig2 = check_demo_signal("https://suspicious-example.test", "suspicious-example.test")
        self.assertIsNotNone(sig2)
        self.assertEqual(sig2["status"], STATUS_SUSPICIOUS)

        # Safe pattern
        sig3 = check_demo_signal("https://wikipedia.org", "wikipedia.org")
        self.assertIsNotNone(sig3)
        self.assertEqual(sig3["status"], STATUS_SAFE)

    def test_batch_url_deduplication(self):
        urls = [
            "https://wikipedia.org",
            "https://wikipedia.org#section1",
            "https://wikipedia.org#section2",
            "https://malicious-example.test/fake-login"
        ]
        results = check_multiple_urls(urls, force_demo=True)
        # Should return results for all 4 inputs preserving array mapping
        self.assertEqual(len(results), 4)
        # The malicious test url should be flagged
        malicious_res = [r for r in results if "malicious" in r["url"]]
        self.assertTrue(len(malicious_res) > 0)
        self.assertEqual(malicious_res[0]["status"], STATUS_MALICIOUS)


if __name__ == "__main__":
    unittest.main()
