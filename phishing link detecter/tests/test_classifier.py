"""
Unit Tests for Multi-Source Threat Classifier Decision Module
"""

import unittest
import sys
import os

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from threat_classifier import (
    ThreatClassifier,
    STATUS_SAFE,
    STATUS_SUSPICIOUS,
    STATUS_MALICIOUS,
    STATUS_UNKNOWN,
    REASON_PHISHING,
    REASON_MALWARE,
    REASON_NO_THREAT,
    REASON_UNVERIFIED
)


class TestThreatClassifier(unittest.TestCase):
    def test_gsb_social_engineering_classified_as_malicious(self):
        gsb = {"detected": True, "threat_type": "SOCIAL_ENGINEERING", "error": False}
        verdict = ThreatClassifier.classify(gsb_result=gsb)
        self.assertEqual(verdict["status"], STATUS_MALICIOUS)
        self.assertEqual(verdict["threat_type"], "Phishing")
        self.assertIn("Google Safe Browsing", verdict["sources"])

    def test_gsb_malware_classified_as_malicious(self):
        gsb = {"detected": True, "threat_type": "MALWARE", "error": False}
        verdict = ThreatClassifier.classify(gsb_result=gsb)
        self.assertEqual(verdict["status"], STATUS_MALICIOUS)
        self.assertEqual(verdict["threat_type"], "Malware")

    def test_virustotal_high_consensus_classified_as_malicious(self):
        vt = {"malicious": 4, "suspicious": 1, "harmless": 40, "error": False}
        verdict = ThreatClassifier.classify(vt_result=vt)
        self.assertEqual(verdict["status"], STATUS_MALICIOUS)
        self.assertIn("VirusTotal API", verdict["sources"])

    def test_virustotal_low_consensus_classified_as_suspicious(self):
        vt = {"malicious": 1, "suspicious": 0, "harmless": 50, "error": False}
        verdict = ThreatClassifier.classify(vt_result=vt)
        self.assertEqual(verdict["status"], STATUS_SUSPICIOUS)

    def test_all_sources_clean_classified_as_safe(self):
        gsb = {"detected": False, "threat_type": None, "error": False}
        vt = {"malicious": 0, "suspicious": 0, "harmless": 70, "error": False}
        verdict = ThreatClassifier.classify(gsb_result=gsb, vt_result=vt)
        self.assertEqual(verdict["status"], STATUS_SAFE)
        self.assertEqual(verdict["reason"], REASON_NO_THREAT)

    def test_apis_failing_classified_as_unknown(self):
        # Critical viva principle: When services are down, do NOT say "Safe"! Say "Unable to verify".
        gsb = {"detected": False, "error": True, "message": "Timeout"}
        vt = {"error": True, "message": "Quota exceeded"}
        verdict = ThreatClassifier.classify(gsb_result=gsb, vt_result=vt)
        self.assertEqual(verdict["status"], STATUS_UNKNOWN)
        self.assertEqual(verdict["reason"], REASON_UNVERIFIED)

    def test_demo_signal_takes_precedence(self):
        demo = {
            "status": STATUS_MALICIOUS,
            "threat_type": "Phishing Demo",
            "reason": "Simulated phishing attack test"
        }
        verdict = ThreatClassifier.classify(demo_signal=demo)
        self.assertEqual(verdict["status"], STATUS_MALICIOUS)
        self.assertIn("Heuristics & Threat Engine", verdict["sources"])


if __name__ == "__main__":
    unittest.main()
