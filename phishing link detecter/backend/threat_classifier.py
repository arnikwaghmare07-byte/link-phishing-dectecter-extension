"""
Threat Classifier & Decision Module for Phishing & Malicious Link Alert
Aggregates reputation data from multiple security sources (Google Safe Browsing,
VirusTotal, and Heuristic/Demo engine) into a unified threat classification.

Viva Core Concepts:
- Never claim "100% mathematically safe"; instead report "No threat detected by available sources".
- If security services fail or time out, return "UNKNOWN" ("Unable to verify") rather than falsely reporting safe.
"""

# Supported Threat Verdicts
STATUS_SAFE = "safe"
STATUS_SUSPICIOUS = "suspicious"
STATUS_MALICIOUS = "malicious"
STATUS_UNKNOWN = "unknown"

# Common Threat Reasons
REASON_PHISHING = "Phishing / Social Engineering detected"
REASON_MALWARE = "Malware / Unwanted Software detected"
REASON_SUSPICIOUS_DOMAIN = "Suspicious domain or deceptive pattern detected"
REASON_VIRUSTOTAL_MALICIOUS = "Flagged malicious by multiple antivirus security vendors"
REASON_VIRUSTOTAL_SUSPICIOUS = "Flagged suspicious by security vendor"
REASON_NO_THREAT = "No threat detected by available security sources"
REASON_UNVERIFIED = "Unable to verify link reputation (security services unavailable)"


class ThreatClassifier:
    @staticmethod
    def classify(gsb_result=None, vt_result=None, demo_signal=None):
        """
        Multi-Source Decision Matrix:
        Aggregates results from Google Safe Browsing, VirusTotal, and Demo/Heuristics.

        Parameters:
            gsb_result (dict): {"threat_type": "...", "detected": bool, "error": bool}
            vt_result (dict): {"malicious": int, "suspicious": int, "harmless": int, "undetected": int, "error": bool}
            demo_signal (dict): {"status": "...", "threat_type": "...", "reason": "..."}

        Returns:
            dict: {
                "status": "safe" | "suspicious" | "malicious" | "unknown",
                "threat_type": str | None,
                "reason": str,
                "sources": list of str
            }
        """
        sources = []

        # 1. Check Demo / Simulation Signal (Highest priority if in Demo Mode)
        if demo_signal and demo_signal.get("status"):
            status = demo_signal["status"]
            return {
                "status": status,
                "threat_type": demo_signal.get("threat_type"),
                "reason": demo_signal.get("reason", "Simulated threat database verdict"),
                "sources": ["Heuristics & Threat Engine"]
            }

        # Track external security source responses
        gsb_detected = False
        gsb_threat = None
        vt_malicious_count = 0
        vt_suspicious_count = 0
        all_failed = True

        # 2. Evaluate Google Safe Browsing Result
        if gsb_result and not gsb_result.get("error"):
            all_failed = False
            sources.append("Google Safe Browsing")
            if gsb_result.get("detected"):
                gsb_detected = True
                gsb_threat = gsb_result.get("threat_type")

        # 3. Evaluate VirusTotal Result
        if vt_result and not vt_result.get("error"):
            all_failed = False
            sources.append("VirusTotal API")
            vt_malicious_count = vt_result.get("malicious", 0)
            vt_suspicious_count = vt_result.get("suspicious", 0)

        # 4. If all active security APIs failed or returned errors
        if all_failed:
            return {
                "status": STATUS_UNKNOWN,
                "threat_type": "Service Unavailable",
                "reason": REASON_UNVERIFIED,
                "sources": sources if sources else ["None (APIs Unreachable)"]
            }

        # 5. Multi-Source Decision Rules:

        # RULE A: Direct high-confidence malicious match from Google Safe Browsing
        if gsb_detected:
            if gsb_threat in ["SOCIAL_ENGINEERING", "THREAT_TYPE_UNSPECIFIED"]:
                return {
                    "status": STATUS_MALICIOUS,
                    "threat_type": "Phishing",
                    "reason": REASON_PHISHING,
                    "sources": sources
                }
            elif gsb_threat in ["MALWARE", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]:
                return {
                    "status": STATUS_MALICIOUS,
                    "threat_type": "Malware",
                    "reason": REASON_MALWARE,
                    "sources": sources
                }
            else:
                return {
                    "status": STATUS_MALICIOUS,
                    "threat_type": gsb_threat or "Malicious",
                    "reason": f"Flagged by Google Safe Browsing as {gsb_threat}",
                    "sources": sources
                }

        # RULE B: Strong VirusTotal consensus (>= 2 security engines flag malicious)
        if vt_malicious_count >= 2:
            return {
                "status": STATUS_MALICIOUS,
                "threat_type": "Multi-Vendor Malware/Phishing",
                "reason": f"{REASON_VIRUSTOTAL_MALICIOUS} ({vt_malicious_count} engines)",
                "sources": sources
            }

        # RULE C: Moderate / Suspicious detection (1 VT malicious engine or >= 1 suspicious engine)
        if vt_malicious_count == 1 or vt_suspicious_count >= 1:
            return {
                "status": STATUS_SUSPICIOUS,
                "threat_type": "Suspicious Activity",
                "reason": f"{REASON_VIRUSTOTAL_SUSPICIOUS} (Engines: {vt_malicious_count} malicious, {vt_suspicious_count} suspicious)",
                "sources": sources
            }

        # RULE D: All verified sources report clean (0 threats)
        return {
            "status": STATUS_SAFE,
            "threat_type": None,
            "reason": REASON_NO_THREAT,
            "sources": sources
        }
