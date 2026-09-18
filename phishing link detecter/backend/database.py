"""
Database Module for Phishing & Malicious Link Alert
Uses SQLite to store URL reputation scan results and history locally.
"""

import sqlite3
import os
import json
from datetime import datetime, timedelta, timezone

# Database file location in the backend folder
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")


def get_connection():
    """Create a connection to SQLite with row-factory enabled for dictionary-like access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initializes the SQLite database and creates the `scan_results` table if it does not exist.
    Called on backend startup.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            domain TEXT NOT NULL,
            status TEXT NOT NULL,
            threat_type TEXT,
            reason TEXT,
            sources TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def save_scan_result(url, domain, status, threat_type, reason, sources):
    """
    Saves or updates a URL reputation result in the SQLite database.
    """
    conn = get_connection()
    cursor = conn.cursor()
    
    # Store sources list as JSON string for clean serialization
    sources_json = json.dumps(sources) if isinstance(sources, list) else str(sources)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO scan_results (url, domain, status, threat_type, reason, sources, scanned_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(url) DO UPDATE SET
            domain=excluded.domain,
            status=excluded.status,
            threat_type=excluded.threat_type,
            reason=excluded.reason,
            sources=excluded.sources,
            scanned_at=excluded.scanned_at
    """, (url, domain, status, threat_type, reason, sources_json, now_str))

    conn.commit()
    conn.close()


def get_cached_scan(url, max_age_hours=24):
    """
    Retrieves a cached scan result from the database if it is not older than `max_age_hours`.
    Returns None if not found or expired.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_results WHERE url = ?", (url,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    # Check expiration
    scanned_at_str = row["scanned_at"]
    try:
        scanned_at = datetime.strptime(scanned_at_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - scanned_at > timedelta(hours=max_age_hours):
            return None  # Expired
    except Exception:
        pass

    try:
        sources_list = json.loads(row["sources"])
    except Exception:
        sources_list = [row["sources"]] if row["sources"] else []

    return {
        "url": row["url"],
        "domain": row["domain"],
        "status": row["status"],
        "threat_type": row["threat_type"],
        "reason": row["reason"],
        "sources": sources_list,
        "scanned_at": row["scanned_at"],
        "cached": True
    }


def get_scan_history(limit=50):
    """
    Fetches the latest scan records for presentation and testing.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_results ORDER BY scanned_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()

    history = []
    for row in rows:
        try:
            sources = json.loads(row["sources"])
        except Exception:
            sources = [row["sources"]] if row["sources"] else []

        history.append({
            "id": row["id"],
            "url": row["url"],
            "domain": row["domain"],
            "status": row["status"],
            "threat_type": row["threat_type"],
            "reason": row["reason"],
            "sources": sources,
            "scanned_at": row["scanned_at"]
        })
    return history


def clear_history():
    """Clears all scan history from the database (useful for resetting demos)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_results")
    conn.commit()
    conn.close()


# Ensure database table is created immediately on module load
try:
    init_db()
except Exception as e:
    print(f"[Database Warning] Could not auto-initialize DB: {e}")

