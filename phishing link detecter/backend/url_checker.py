"""
URL Checker & Security API Integrator
Handles URL validation, canonical normalization, external API requests
(Google Safe Browsing v4, VirusTotal v3), and built-in Demo Simulation.
"""

import os
import sys
import re
import base64
import requests
from urllib.parse import urlparse, urlunparse

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from cache import URLCache
from threat_classifier import (
    ThreatClassifier,
    STATUS_SAFE,
    STATUS_SUSPICIOUS,
    STATUS_MALICIOUS,
    STATUS_UNKNOWN,
    REASON_PHISHING,
    REASON_MALWARE,
    REASON_SUSPICIOUS_DOMAIN,
    REASON_NO_THREAT
)

# Simulated Threat Patterns for College Presentations and Safe Testing
DEMO_PATTERNS = {
    STATUS_MALICIOUS: [
        "malicious-example.test",
        "paypal-secure-login-fake.com",
        "malware-payload.test",
        "banking-credential-steal.xyz",
        "urgent-account-suspended.cc",
        "free-giftcard-scam.biz",
        "malicious",
        "phishing-demo"
    ],
    STATUS_SUSPICIOUS: [
        "suspicious-example.test",
        "update-account-alert.net",
        "security-verify-login.xyz",
        "claim-bonus-now.top",
        "suspicious",
        "unverified-login"
    ],
    STATUS_SAFE: [
        "safe-example.test",
        "google.com",
        "wikipedia.org",
        "python.org",
        "github.com",
        "stackoverflow.com",
        "microsoft.com"
    ]
}


def normalize_url(raw_url):
    """
    Validates and normalizes a raw URL.
    - Strips leading/trailing whitespaces.
    - Ensures valid http/https scheme.
    - Lowercases the hostname.
    - Removes URL fragments (#section).
    Returns (normalized_url, domain) or (None, None) if invalid.
    """
    if not raw_url or not isinstance(raw_url, str):
        return None, None

    clean_url = raw_url.strip()

    # Reject non-web schemes
    if clean_url.startswith(("javascript:", "mailto:", "tel:", "chrome:", "edge:", "about:", "#")):
        return None, None

    # Prepend http:// if missing scheme for parsing
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "https://" + clean_url

    try:
        parsed = urlparse(clean_url)
        hostname = parsed.hostname
        if not hostname or "." not in hostname:
            return None, None

        # Lowercase domain, strip fragment
        normalized_hostname = hostname.lower()
        port_part = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        netloc = f"{normalized_hostname}{port_part}"
        
        # Keep path and query, remove fragment
        normalized = urlunparse((
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            ""  # empty fragment
        ))
        return normalized, normalized_hostname
    except Exception:
        return None, None


def check_demo_signal(url, domain):
    """
    Checks if a URL matches demo test patterns for safe college testing without live malware.
    """
    url_lower = url.lower()
    domain_lower = domain.lower()

    # Check for Malicious indicators
    for pattern in DEMO_PATTERNS[STATUS_MALICIOUS]:
        if pattern in domain_lower or pattern in url_lower:
            return {
                "status": STATUS_MALICIOUS,
                "threat_type": "Phishing / Malware Demo",
                "reason": f"Simulated detection: flagged in demonstration database as {pattern}"
            }

    # Check for Suspicious indicators
    for pattern in DEMO_PATTERNS[STATUS_SUSPICIOUS]:
        if pattern in domain_lower or pattern in url_lower:
            return {
                "status": STATUS_SUSPICIOUS,
                "threat_type": "Suspicious Pattern Demo",
                "reason": f"Simulated detection: suspicious domain keyword '{pattern}'"
            }

    # Check for known safe indicators
    for pattern in DEMO_PATTERNS[STATUS_SAFE]:
        if pattern in domain_lower:
            return {
                "status": STATUS_SAFE,
                "threat_type": None,
                "reason": REASON_NO_THREAT
            }

    return None


def query_google_safe_browsing(url, api_key):
    """
    Queries Google Safe Browsing API v4 threatMatches:find.
    Returns {"detected": bool, "threat_type": str, "error": bool}
    """
    if not api_key:
        return {"detected": False, "threat_type": None, "error": True, "message": "No API key"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {
            "clientId": "phishing-malicious-link-alert",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            if matches:
                first_match = matches[0]
                return {
                    "detected": True,
                    "threat_type": first_match.get("threatType", "MALICIOUS"),
                    "error": False
                }
            return {"detected": False, "threat_type": None, "error": False}
        else:
            return {"detected": False, "threat_type": None, "error": True, "code": response.status_code}
    except Exception as e:
        return {"detected": False, "threat_type": None, "error": True, "message": str(e)}


def query_virustotal(url, api_key):
    """
    Queries VirusTotal API v3 /urls/{id}.
    Returns {"malicious": int, "suspicious": int, "harmless": int, "undetected": int, "error": bool}
    """
    if not api_key:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "error": True, "message": "No API key"}

    try:
        # VirusTotal v3 requires base64 URL identifier without padding
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }

        response = requests.get(endpoint, headers=headers, timeout=6)
        if response.status_code == 200:
            stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "error": False
            }
        elif response.status_code == 404:
            # URL not yet analyzed in VirusTotal database
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "error": False}
        else:
            return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "error": True, "code": response.status_code}
    except Exception as e:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0, "error": True, "message": str(e)}


def check_url_reputation(raw_url, force_demo=None):
    """
    Comprehensive single URL reputation check:
    1. Normalizes and validates the URL.
    2. Checks the local cache (Memory & SQLite).
    3. Evaluates Demo Mode simulation signals if enabled.
    4. Queries configured Security APIs (Google Safe Browsing & VirusTotal).
    5. Feeds signals into the multi-source ThreatClassifier.
    6. Stores verdict in cache and returns standardized response.
    """
    norm_url, domain = normalize_url(raw_url)
    if not norm_url:
        return {
            "url": raw_url,
            "domain": None,
            "status": STATUS_UNKNOWN,
            "threat_type": "Invalid URL",
            "reason": "URL format is invalid or unsupported scheme",
            "sources": []
        }

    # 1. Check Cache
    cached = URLCache.get(norm_url)
    if cached:
        return cached

    # Determine Demo Mode setting
    env_demo = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")
    is_demo = force_demo if force_demo is not None else env_demo

    demo_signal = None
    if is_demo:
        demo_signal = check_demo_signal(norm_url, domain)

    # API Keys
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    # Query APIs if keys present
    gsb_result = query_google_safe_browsing(norm_url, gsb_key) if gsb_key else None
    vt_result = query_virustotal(norm_url, vt_key) if vt_key else None

    # If in demo mode and no API keys are set, provide safe fallback for unlisted URLs
    if is_demo and not demo_signal and not gsb_key and not vt_key:
        demo_signal = {
            "status": STATUS_SAFE,
            "threat_type": None,
            "reason": "No threat detected (Demo Mode simulated scan)"
        }

    # Classify verdict using multi-source decision module
    verdict = ThreatClassifier.classify(
        gsb_result=gsb_result,
        vt_result=vt_result,
        demo_signal=demo_signal
    )

    # Cache verdict
    URLCache.set(
        url=norm_url,
        domain=domain,
        status=verdict["status"],
        threat_type=verdict.get("threat_type"),
        reason=verdict.get("reason"),
        sources=verdict.get("sources", [])
    )

    return {
        "url": norm_url,
        "domain": domain,
        "status": verdict["status"],
        "threat_type": verdict.get("threat_type"),
        "reason": verdict.get("reason"),
        "sources": verdict.get("sources", []),
        "cached": False
    }


def check_multiple_urls(urls, force_demo=None, max_batch=100):
    """
    Checks multiple URLs efficiently with deduplication and batching protection.
    """
    if not urls or not isinstance(urls, list):
        return []

    # Enforce safe batch size limit to protect backend resources
    safe_urls = urls[:max_batch]
    results_map = {}
    unique_urls = []

    for raw_url in safe_urls:
        norm_url, _ = normalize_url(raw_url)
        key = norm_url or raw_url
        if key not in results_map:
            results_map[key] = None
            unique_urls.append((raw_url, key))

    # Process unique URLs
    for raw_url, key in unique_urls:
        results_map[key] = check_url_reputation(raw_url, force_demo=force_demo)

    # Return results in order
    output = []
    for raw_url in safe_urls:
        norm_url, _ = normalize_url(raw_url)
        key = norm_url or raw_url
        res = results_map.get(key)
        if res:
            # Return copy with original raw URL preserved
            item = dict(res)
            item["original_url"] = raw_url
            output.append(item)

    return output
