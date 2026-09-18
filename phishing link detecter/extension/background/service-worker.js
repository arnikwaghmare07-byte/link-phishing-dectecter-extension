/**
 * Background Service Worker (Manifest V3)
 * Phishing & Malicious Link Alert
 * 
 * Responsibilities:
 * 1. Coordinates communication between Content Scripts, Popup UI, and Flask Backend.
 * 2. Caches reputation responses in chrome.storage to reduce backend network requests.
 * 3. Tracks real-time tab statistics (total scanned, safe, suspicious, malicious).
 * 4. Manages extension badge alerts on the toolbar icon.
 */

const DEFAULT_SETTINGS = {
  protection_enabled: true,
  auto_scan: true,
  highlight_links: true,
  warn_before_click: true,
  demo_mode: true,
  backend_url: "http://localhost:5000"
};

// In-memory tab statistics tracker: tabId -> { total, safe, suspicious, malicious, unknown, domain, lastScan }
const tabStats = {};

// Initialize default settings upon installation
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[Service Worker] Extension installed / updated.");
  const current = await chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS));
  const toSet = {};
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
    if (current[k] === undefined) {
      toSet[k] = v;
    }
  }
  if (Object.keys(toSet).length > 0) {
    await chrome.storage.local.set(toSet);
  }
});

// Clean up tab stats when a tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  delete tabStats[tabId];
});

/**
 * Updates the extension toolbar badge for a given tab.
 */
function updateBadge(tabId, stats) {
  if (!tabId || !stats) return;

  try {
    if (stats.malicious > 0) {
      chrome.action.setBadgeText({ tabId, text: String(stats.malicious) });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#ef4444" }); // Red
    } else if (stats.suspicious > 0) {
      chrome.action.setBadgeText({ tabId, text: String(stats.suspicious) });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#f59e0b" }); // Orange
    } else if (stats.total > 0) {
      chrome.action.setBadgeText({ tabId, text: "OK" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#10b981" }); // Green
    } else {
      chrome.action.setBadgeText({ tabId, text: "" });
    }
  } catch (err) {
    // Tab might have navigated away
    console.warn("[Service Worker] Badge update skipped:", err);
  }
}

/**
 * Listen for messages from Content Script and Popup UI
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab ? sender.tab.id : null;

  if (message.action === "CHECK_URLS") {
    handleCheckUrls(message.urls, tabId, message.domain)
      .then(sendResponse)
      .catch((err) => {
        console.error("[Service Worker] Error checking URLs:", err);
        sendResponse({ error: err.message, results: [] });
      });
    return true; // Keep channel open for async response
  }

  if (message.action === "GET_TAB_STATS") {
    const targetTabId = message.tabId || tabId;
    const stats = tabStats[targetTabId] || {
      total: 0,
      safe: 0,
      suspicious: 0,
      malicious: 0,
      unknown: 0,
      domain: "Unknown",
      lastScan: "Not yet scanned"
    };
    sendResponse({ stats });
    return false;
  }

  if (message.action === "GET_SETTINGS") {
    chrome.storage.local.get(DEFAULT_SETTINGS).then((settings) => {
      sendResponse({ settings });
    });
    return true;
  }

  if (message.action === "SAVE_SETTINGS") {
    chrome.storage.local.set(message.settings).then(() => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.action === "OPEN_WARNING_PAGE") {
    const query = new URLSearchParams({
      url: message.url || "",
      status: message.status || "malicious",
      reason: message.reason || "Suspicious or malicious activity detected",
      threat_type: message.threat_type || "Threat Detected",
      sources: JSON.stringify(message.sources || [])
    }).toString();

    const warningUrl = chrome.runtime.getURL(`warning/warning.html?${query}`);
    chrome.tabs.create({ url: warningUrl });
    sendResponse({ success: true });
    return false;
  }
});

/**
 * Sends URL batch to the Python Flask backend with deduplication and error recovery.
 */
async function handleCheckUrls(urls, tabId, pageDomain) {
  const settings = await chrome.storage.local.get(DEFAULT_SETTINGS);

  if (!settings.protection_enabled) {
    return {
      protection_disabled: true,
      total: 0,
      summary: { safe: 0, suspicious: 0, malicious: 0, unknown: 0 },
      results: []
    };
  }

  const backendUrl = settings.backend_url || "http://localhost:5000";
  const endpoint = `${backendUrl}/api/check-urls`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000); // 8-second network timeout

    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        urls: urls,
        demo_mode: settings.demo_mode
      }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`Backend returned HTTP status ${response.status}`);
    }

    const data = await response.json();

    // Store statistics for the current tab
    if (tabId) {
      const now = new Date();
      const timeStr = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      
      tabStats[tabId] = {
        total: data.total || 0,
        safe: data.summary ? data.summary.safe : 0,
        suspicious: data.summary ? data.summary.suspicious : 0,
        malicious: data.summary ? data.summary.malicious : 0,
        unknown: data.summary ? data.summary.unknown : 0,
        domain: pageDomain || "Current Page",
        lastScan: timeStr,
        results: data.results || []
      };

      updateBadge(tabId, tabStats[tabId]);
    }

    return data;
  } catch (error) {
    console.warn("[Service Worker] Backend communication failed:", error.message);

    // Fallback: Return UNKNOWN status for all scanned URLs when backend is offline
    const fallbackResults = urls.map((u) => ({
      url: u,
      original_url: u,
      status: "unknown",
      threat_type: "Backend Offline",
      reason: "Could not reach Python backend (start 'python app.py' on port 5000)",
      sources: ["Offline Fallback"]
    }));

    if (tabId) {
      tabStats[tabId] = {
        total: urls.length,
        safe: 0,
        suspicious: 0,
        malicious: 0,
        unknown: urls.length,
        domain: pageDomain || "Current Page",
        lastScan: "Backend Offline",
        results: fallbackResults
      };
      updateBadge(tabId, tabStats[tabId]);
    }

    return {
      total: urls.length,
      summary: { safe: 0, suspicious: 0, malicious: 0, unknown: urls.length },
      results: fallbackResults,
      backend_offline: true
    };
  }
}
