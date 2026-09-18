"""
Cache Module for Phishing & Malicious Link Alert
Implements an in-memory TTL (Time-To-Live) cache with SQLite persistence fallback.
Why caching is essential:
1. Prevents duplicate API calls for identical links on the same webpage.
2. Drastically cuts latency (<1ms memory response).
3. Conserves free-tier API quotas (Google Safe Browsing & VirusTotal).
"""

import time
import os
import sys

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from database import get_cached_scan, save_scan_result

DEFAULT_EXPIRY_SECONDS = int(os.getenv("CACHE_EXPIRY_HOURS", 24)) * 3600

# In-memory dictionary: { normalized_url: {"data": {...}, "expires_at": float_timestamp} }
_MEMORY_CACHE = {}


class URLCache:
    @staticmethod
    def get(url):
        """
        Lookup URL reputation from memory first, then SQLite database.
        Returns cached data dict if valid and unexpired, otherwise None.
        """
        now = time.time()

        # 1. Check in-memory cache
        if url in _MEMORY_CACHE:
            entry = _MEMORY_CACHE[url]
            if entry["expires_at"] > now:
                res = dict(entry["data"])
                res["cached"] = True
                res["cache_layer"] = "memory"
                return res
            else:
                # Expired in memory
                del _MEMORY_CACHE[url]

        # 2. Check SQLite persistent cache
        max_age_hours = int(os.getenv("CACHE_EXPIRY_HOURS", 24))
        db_result = get_cached_scan(url, max_age_hours=max_age_hours)
        if db_result:
            # Re-populate in-memory cache
            _MEMORY_CACHE[url] = {
                "data": db_result,
                "expires_at": now + DEFAULT_EXPIRY_SECONDS
            }
            db_result["cache_layer"] = "sqlite"
            return db_result

        return None

    @staticmethod
    def set(url, domain, status, threat_type, reason, sources):
        """
        Stores URL reputation in both in-memory cache and SQLite database.
        """
        now = time.time()
        data = {
            "url": url,
            "domain": domain,
            "status": status,
            "threat_type": threat_type,
            "reason": reason,
            "sources": sources
        }

        # Save to memory cache
        _MEMORY_CACHE[url] = {
            "data": data,
            "expires_at": now + DEFAULT_EXPIRY_SECONDS
        }

        # Save to SQLite database
        try:
            save_scan_result(url, domain, status, threat_type, reason, sources)
        except Exception as e:
            print(f"[Cache Warning] Failed to persist to SQLite: {e}")

    @staticmethod
    def clear():
        """Clears in-memory cache."""
        _MEMORY_CACHE.clear()
