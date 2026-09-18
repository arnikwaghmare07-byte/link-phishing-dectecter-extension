/**
 * Popup Script: Phishing Guard UI Controller
 * Communicates with Background Service Worker and Chrome Storage.
 */

document.addEventListener("DOMContentLoaded", async () => {
  // DOM Elements
  const domainNameEl = document.getElementById("domainName");
  const lastScanTimeEl = document.getElementById("lastScanTime");
  const statSafeEl = document.getElementById("statSafe");
  const statSuspiciousEl = document.getElementById("statSuspicious");
  const statMaliciousEl = document.getElementById("statMalicious");
  const statUnknownEl = document.getElementById("statUnknown");
  const statusPill = document.getElementById("statusPill");
  const statusText = document.getElementById("statusText");
  const demoBanner = document.getElementById("demoBanner");

  const scanBtn = document.getElementById("scanBtn");
  const detailsBtn = document.getElementById("detailsBtn");
  const settingsBtn = document.getElementById("settingsBtn");

  const detailsPanel = document.getElementById("detailsPanel");
  const settingsPanel = document.getElementById("settingsPanel");
  const detailsList = document.getElementById("detailsList");

  const toggleProtection = document.getElementById("toggleProtection");
  const toggleAutoScan = document.getElementById("toggleAutoScan");
  const toggleHighlight = document.getElementById("toggleHighlight");
  const toggleWarnClick = document.getElementById("toggleWarnClick");
  const toggleDemoMode = document.getElementById("toggleDemoMode");

  // 1. Get Active Tab
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (activeTab && activeTab.url) {
    try {
      const parsed = new URL(activeTab.url);
      domainNameEl.textContent = parsed.hostname || "Local / File";
    } catch (e) {
      domainNameEl.textContent = "Current Tab";
    }
  }

  // 2. Load Settings from Storage
  chrome.runtime.sendMessage({ action: "GET_SETTINGS" }, (res) => {
    if (res && res.settings) {
      const s = res.settings;
      toggleProtection.checked = s.protection_enabled !== false;
      toggleAutoScan.checked = s.auto_scan !== false;
      toggleHighlight.checked = s.highlight_links !== false;
      toggleWarnClick.checked = s.warn_before_click !== false;
      toggleDemoMode.checked = s.demo_mode !== false;

      updateProtectionPill(s.protection_enabled !== false);
      demoBanner.style.display = s.demo_mode ? "block" : "none";
    }
  });

  // 3. Load Tab Statistics
  if (activeTab) {
    chrome.runtime.sendMessage(
      { action: "GET_TAB_STATS", tabId: activeTab.id },
      (res) => {
        if (res && res.stats) {
          const stats = res.stats;
          statSafeEl.textContent = stats.safe || 0;
          statSuspiciousEl.textContent = stats.suspicious || 0;
          statMaliciousEl.textContent = stats.malicious || 0;
          statUnknownEl.textContent = stats.unknown || 0;

          if (stats.domain && stats.domain !== "Unknown") {
            domainNameEl.textContent = stats.domain;
          }
          lastScanTimeEl.textContent = stats.lastScan || "--:--";

          renderDetails(stats.results || []);
        }
      }
    );
  }

  function updateProtectionPill(isEnabled) {
    if (isEnabled) {
      statusPill.className = "status-pill status-active";
      statusText.textContent = "Active";
    } else {
      statusPill.className = "status-pill status-paused";
      statusText.textContent = "Paused";
    }
  }

  function renderDetails(results) {
    const flagged = results.filter((r) => r.status === "malicious" || r.status === "suspicious");
    if (flagged.length === 0) {
      detailsList.innerHTML = `<div style="color: #94a3b8; text-align: center; padding: 10px;">No dangerous links detected on this page.</div>`;
      return;
    }

    detailsList.innerHTML = flagged
      .map((item) => {
        const isMal = item.status === "malicious";
        const color = isMal ? "#f87171" : "#fbbf24";
        const icon = isMal ? "🛑" : "⚠️";
        return `
          <div class="detail-item">
            <span style="color:${color}; font-weight:700;">${icon} ${item.status.toUpperCase()}</span>
            <div style="color:#e2e8f0; font-family:monospace; margin:2px 0;">${escapeHtml(item.url)}</div>
            <div style="color:#94a3b8; font-size:10px;">${escapeHtml(item.reason || "")}</div>
          </div>
        `;
      })
      .join("");
  }

  function escapeHtml(text) {
    if (!text) return "";
    return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  // Button Listeners
  scanBtn.addEventListener("click", () => {
    scanBtn.textContent = "⏳ Scanning...";
    if (activeTab) {
      chrome.scripting ? 
        chrome.scripting.executeScript({
          target: { tabId: activeTab.id },
          func: () => window.location.reload()
        }) : 
        chrome.tabs.reload(activeTab.id);
    }
    setTimeout(() => {
      window.close();
    }, 600);
  });

  detailsBtn.addEventListener("click", () => {
    detailsPanel.classList.toggle("open");
    settingsPanel.classList.remove("open");
  });

  settingsBtn.addEventListener("click", () => {
    settingsPanel.classList.toggle("open");
    detailsPanel.classList.remove("open");
  });

  // Setting Toggle Listeners
  function saveSettings() {
    const settings = {
      protection_enabled: toggleProtection.checked,
      auto_scan: toggleAutoScan.checked,
      highlight_links: toggleHighlight.checked,
      warn_before_click: toggleWarnClick.checked,
      demo_mode: toggleDemoMode.checked
    };

    chrome.runtime.sendMessage({ action: "SAVE_SETTINGS", settings });
    updateProtectionPill(settings.protection_enabled);
    demoBanner.style.display = settings.demo_mode ? "block" : "none";
  }

  toggleProtection.addEventListener("change", saveSettings);
  toggleAutoScan.addEventListener("change", saveSettings);
  toggleHighlight.addEventListener("change", saveSettings);
  toggleWarnClick.addEventListener("change", saveSettings);
  toggleDemoMode.addEventListener("change", saveSettings);
});
