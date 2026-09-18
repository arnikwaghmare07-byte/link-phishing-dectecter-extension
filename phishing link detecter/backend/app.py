"""
Flask API Server for Phishing & Malicious Link Alert
Provides RESTful endpoints for the Chrome Extension:
- POST /api/check-url
- POST /api/check-urls
- GET  /api/health
- GET  /api/history
- GET  /test/safe, /test/suspicious, /test/malicious
"""

import os
import sys
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from dotenv import load_dotenv

# Ensure backend directory is in sys.path for robust imports regardless of invocation directory
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# Load environment variables
load_dotenv(os.path.join(BACKEND_DIR, ".env"))

from database import init_db, get_scan_history, clear_history
from url_checker import check_url_reputation, check_multiple_urls
from cache import URLCache

app = Flask(__name__)
# Enable CORS for Chrome Extension requests and local frontend testing
CORS(app, resources={r"/*": {"origins": "*"}})

# Initialize SQLite database on boot
init_db()


@app.route("/", methods=["GET"])
def home():
    """Simple status dashboard for teachers and examiners."""
    gsb_active = bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip())
    vt_active = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())
    demo_active = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")

    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Phishing & Malicious Link Alert API</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; margin: 0; }
            .card { max-width: 700px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
            h1 { margin-top: 0; color: #38bdf8; display: flex; align-items: center; gap: 12px; }
            .badge { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 13px; font-weight: 600; margin-right: 8px; }
            .badge-on { background: #065f46; color: #34d399; }
            .badge-off { background: #374151; color: #9ca3af; }
            .endpoint { background: #0f172a; padding: 10px 14px; border-radius: 6px; font-family: monospace; font-size: 14px; margin: 6px 0; color: #7dd3fc; border: 1px solid #334155; }
            a { color: #38bdf8; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .stat-box { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 20px 0; }
            .stat-item { background: #0f172a; padding: 14px; border-radius: 8px; text-align: center; border: 1px solid #334155; }
            .stat-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; }
            .stat-val { font-size: 18px; font-weight: 700; margin-top: 6px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ Phishing Link Alert Backend</h1>
            <p>Secure Threat Reputation Service & Multi-Source Decision Engine.</p>
            
            <div class="stat-box">
                <div class="stat-item">
                    <div class="stat-label">Google Safe Browsing</div>
                    <div class="stat-val">""" + ("<span style='color:#34d399;'>Connected</span>" if gsb_active else "<span style='color:#94a3b8;'>Not Configured</span>") + """</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">VirusTotal API</div>
                    <div class="stat-val">""" + ("<span style='color:#34d399;'>Connected</span>" if vt_active else "<span style='color:#94a3b8;'>Not Configured</span>") + """</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">Demo Mode</div>
                    <div class="stat-val">""" + ("<span style='color:#38bdf8;'>ENABLED</span>" if demo_active else "<span style='color:#f87171;'>OFF</span>") + """</div>
                </div>
            </div>

            <h3>Active Endpoints:</h3>
            <div class="endpoint">POST /api/check-url &mdash; Check single URL reputation</div>
            <div class="endpoint">POST /api/check-urls &mdash; Batch URL reputation checking</div>
            <div class="endpoint">GET /api/health &mdash; Server status and health report</div>
            <div class="endpoint">GET /api/history &mdash; View scan history database</div>

            <h3>Simulation & Testing Pages:</h3>
            <p><a href="/test/safe" target="_blank">View Test Safe Page</a> | <a href="/test/suspicious" target="_blank">View Test Suspicious Page</a> | <a href="/test/malicious" target="_blank">View Test Malicious Page</a></p>
        </div>
    </body>
    </html>
    """
    return render_template_string(html)


@app.route("/api/health", methods=["GET"])
def health_check():
    """Returns system status, active integrations, and cache configuration."""
    gsb_configured = bool(os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip())
    vt_configured = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())
    demo_mode = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes")

    return jsonify({
        "status": "online",
        "service": "Phishing & Malicious Link Alert Backend",
        "version": "1.0.0",
        "demo_mode": demo_mode,
        "security_sources": {
            "google_safe_browsing": gsb_configured,
            "virustotal": vt_configured,
            "heuristics_engine": True
        }
    }), 200


@app.route("/api/check-url", methods=["POST"])
def check_single_url():
    """
    Checks the reputation of a single URL.
    Request: {"url": "https://example.com", "demo_mode": bool (optional)}
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    raw_url = data.get("url")
    if not raw_url:
        return jsonify({"error": "Missing 'url' parameter"}), 400

    force_demo = data.get("demo_mode")
    result = check_url_reputation(raw_url, force_demo=force_demo)
    return jsonify(result), 200


@app.route("/api/check-urls", methods=["POST"])
def check_urls_batch():
    """
    Checks reputations for a list of URLs with deduplication and safe batching.
    Request: {"urls": ["https://site1.com", "https://site2.com"], "demo_mode": bool (optional)}
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    urls = data.get("urls", [])
    if not isinstance(urls, list):
        return jsonify({"error": "'urls' must be an array of URL strings"}), 400

    force_demo = data.get("demo_mode")
    results = check_multiple_urls(urls, force_demo=force_demo, max_batch=100)

    # Compute summary counters
    counts = {"safe": 0, "suspicious": 0, "malicious": 0, "unknown": 0}
    for item in results:
        status = item.get("status", "unknown")
        if status in counts:
            counts[status] += 1
        else:
            counts["unknown"] += 1

    return jsonify({
        "total": len(results),
        "summary": counts,
        "results": results
    }), 200


@app.route("/api/history", methods=["GET"])
def history():
    """Returns recent scan logs from the SQLite database."""
    limit = request.args.get("limit", 50, type=int)
    records = get_scan_history(limit=limit)
    return jsonify({
        "count": len(records),
        "history": records
    }), 200


@app.route("/api/clear-history", methods=["POST"])
def clear_scan_history():
    """Clears local scan records and cache (for resetting demonstrations)."""
    clear_history()
    URLCache.clear()
    return jsonify({"message": "Scan history and cache cleared successfully"}), 200


# ==========================================
# TEST PAGES FOR VIVA DEMONSTRATION
# ==========================================
@app.route("/test/safe")
def test_safe():
    return """
    <html>
    <head><title>Test Safe Site</title></head>
    <body style="font-family:sans-serif; padding:40px; text-align:center;">
        <h1 style="color:green;">✅ Verified Safe Website</h1>
        <p>This is a simulated safe destination for testing the extension navigation.</p>
        <a href="javascript:history.back()">Go Back</a>
    </body>
    </html>
    """

@app.route("/test/suspicious")
def test_suspicious():
    return """
    <html>
    <head><title>Test Suspicious Site</title></head>
    <body style="font-family:sans-serif; padding:40px; text-align:center;">
        <h1 style="color:orange;">⚠ Suspicious Website Alert</h1>
        <p>You have reached a simulated suspicious page (used for demonstration testing).</p>
        <a href="javascript:history.back()">Go Back</a>
    </body>
    </html>
    """

@app.route("/test/malicious")
def test_malicious():
    return """
    <html>
    <head><title>Test Malicious Site</title></head>
    <body style="font-family:sans-serif; padding:40px; text-align:center;">
        <h1 style="color:red;">🛑 Malicious Website Simulation</h1>
        <p>This is a simulated dangerous page reached after user explicitly selected 'Proceed Anyway'.</p>
        <a href="javascript:history.back()">Go Back</a>
    </body>
    </html>
    """


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "True").lower() in ("true", "1", "yes")
    print("=" * 60)
    print("🛡️  Phishing & Malicious Link Alert Backend Starting...")
    print(f"📡  Listening on: http://localhost:{port}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=port, debug=debug)
