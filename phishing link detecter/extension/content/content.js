/**
 * Content Script: Phishing & Malicious Link Alert
 * 
 * Responsibilities:
 * 1. Scans all <a> anchor elements on the active webpage.
 * 2. Normalizes, deduplicates, and batches URLs.
 * 3. Communicates with Background Service Worker for threat reputation analysis.
 * 4. Visually highlights malicious (red) and suspicious (orange) links.
 * 5. Provides hover tooltips with threat details.
 * 6. Uses MutationObserver to detect dynamically injected links.
 * 7. Intercepts clicks on flagged links BEFORE browser navigates to prevent harm.
 */

(function () {
  "use strict";

  // Prevent double injection
  if (window.__PHISHING_GUARD_INJECTED__) return;
  window.__PHISHING_GUARD_INJECTED__ = true;

  // Track scanned URLs to avoid re-querying the same link repeatedly on this page
  const scannedUrlMap = new Map(); // normalized_url -> result_object
  let scanDebounceTimer = null;
  let activeTooltip = null;

  console.log("[Phishing Guard] Content script loaded on:", window.location.href);

  /**
   * Normalizes an anchor href attribute into a canonical absolute URL.
   */
  function normalizeLinkHref(rawHref) {
    if (!rawHref) return null;
    const trimmed = rawHref.trim();

    // Ignore non-navigational protocols
    if (
      trimmed.startsWith("javascript:") ||
      trimmed.startsWith("mailto:") ||
      trimmed.startsWith("tel:") ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("about:") ||
      trimmed.startsWith("chrome:")
    ) {
      return null;
    }

    try {
      const parsed = new URL(trimmed, document.baseURI);
      if (!parsed.protocol.startsWith("http")) return null;
      // Strip hash fragment
      parsed.hash = "";
      return parsed.href;
    } catch (e) {
      return null;
    }
  }

  /**
   * Scans all anchor tags in the webpage and batches unverified URLs to the background worker.
   */
  async function scanWebpageLinks() {
    const anchors = Array.from(document.querySelectorAll("a[href]"));
    if (anchors.length === 0) return;

    const urlsToScan = new Set();
    const anchorMap = new Map(); // normalized_url -> array of matching anchor elements

    for (const a of anchors) {
      const normUrl = normalizeLinkHref(a.getAttribute("href"));
      if (!normUrl) continue;

      if (!anchorMap.has(normUrl)) {
        anchorMap.set(normUrl, []);
      }
      anchorMap.get(normUrl).push(a);

      // Check if we already have a verdict for this URL in this session
      if (scannedUrlMap.has(normUrl)) {
        applyVerdictToAnchors(anchorMap.get(normUrl), scannedUrlMap.get(normUrl));
      } else {
        urlsToScan.add(normUrl);
      }
    }

    if (urlsToScan.size === 0) return;

    const uniqueUrlList = Array.from(urlsToScan);
    console.log(`[Phishing Guard] Scanning ${uniqueUrlList.length} unique link(s)...`);

    try {
      chrome.runtime.sendMessage(
        {
          action: "CHECK_URLS",
          urls: uniqueUrlList,
          domain: window.location.hostname
        },
        (response) => {
          if (chrome.runtime.lastError) {
            console.warn("[Phishing Guard] Communication error:", chrome.runtime.lastError.message);
            return;
          }

          if (!response || !response.results) return;

          for (const item of response.results) {
            const key = item.url;
            scannedUrlMap.set(key, item);
            const matchingAnchors = anchorMap.get(key) || [];
            applyVerdictToAnchors(matchingAnchors, item);
          }
        }
      );
    } catch (err) {
      console.warn("[Phishing Guard] Failed to send scan message:", err);
    }
  }

  /**
   * Applies CSS classes and threat metadata to anchor elements based on verdict.
   */
  function applyVerdictToAnchors(anchors, verdict) {
    if (!anchors || !verdict) return;

    for (const a of anchors) {
      // Store threat metadata for click interception and tooltips
      a.dataset.pgStatus = verdict.status;
      a.dataset.pgThreatType = verdict.threat_type || "";
      a.dataset.pgReason = verdict.reason || "";
      a.dataset.pgSources = JSON.stringify(verdict.sources || []);
      a.dataset.pgNormalizedUrl = verdict.url;

      // Remove existing highlight classes
      a.classList.remove("phishing-danger", "suspicious-link");

      if (verdict.status === "malicious") {
        a.classList.add("phishing-danger");
        attachHoverTooltip(a, "🛑 MALICIOUS THREAT DETECTED", verdict.reason, "tooltip-danger");
      } else if (verdict.status === "suspicious") {
        a.classList.add("suspicious-link");
        attachHoverTooltip(a, "⚠️ SUSPICIOUS LINK ALERT", verdict.reason, "tooltip-suspicious");
      }
    }
  }

  /**
   * Attaches clean hover tooltip events to a flagged link.
   */
  function attachHoverTooltip(element, title, reason, cssModifier) {
    if (element.__pgTooltipBound) return;
    element.__pgTooltipBound = true;

    element.addEventListener("mouseenter", (e) => {
      removeActiveTooltip();

      const tooltip = document.createElement("div");
      tooltip.className = `phishing-guard-tooltip ${cssModifier}`;
      tooltip.innerHTML = `
        <div style="font-weight:700; margin-bottom:3px;">${escapeHtml(title)}</div>
        <div style="color:#cbd5e1;">${escapeHtml(reason || "Caution advised before opening.")}</div>
        <div style="font-size:10px; color:#94a3b8; margin-top:4px;">Phishing Guard Protection</div>
      `;

      document.body.appendChild(tooltip);
      activeTooltip = tooltip;

      const rect = element.getBoundingClientRect();
      const topPos = window.scrollY + rect.bottom + 6;
      const leftPos = Math.max(10, window.scrollX + rect.left);

      tooltip.style.top = `${topPos}px`;
      tooltip.style.left = `${leftPos}px`;
    });

    element.addEventListener("mouseleave", () => {
      removeActiveTooltip();
    });
  }

  function removeActiveTooltip() {
    if (activeTooltip && activeTooltip.parentNode) {
      activeTooltip.parentNode.removeChild(activeTooltip);
      activeTooltip = null;
    }
  }

  /**
   * Helper to escape HTML characters in strings for safe DOM rendering.
   */
  function escapeHtml(text) {
    if (!text) return "";
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /**
   * PRE-CLICK INTERCEPTION (Capture Phase)
   * Intercepts clicks on flagged links BEFORE navigation occurs.
   */
  document.addEventListener(
    "click",
    function (e) {
      const anchor = e.target.closest("a[href]");
      if (!anchor) return;

      const status = anchor.dataset.pgStatus;
      if (status === "malicious" || status === "suspicious") {
        // Intercept immediately
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();

        removeActiveTooltip();

        const threatData = {
          url: anchor.href,
          normalized_url: anchor.dataset.pgNormalizedUrl || anchor.href,
          status: status,
          threat_type: anchor.dataset.pgThreatType || "Threat Detected",
          reason: anchor.dataset.pgReason || "Potential security hazard detected.",
          sources: JSON.parse(anchor.dataset.pgSources || "[]")
        };

        showWarningModal(threatData);
      }
    },
    true // Capture phase is critical to run before other page click handlers!
  );

  /**
   * Displays the in-page warning modal with interactive options:
   * [ Go Back to Safety ] or [ Proceed Anyway ].
   */
  function showWarningModal(data) {
    // Remove any existing modal
    const existing = document.getElementById("phishing-guard-modal-overlay");
    if (existing) existing.remove();

    const isMalicious = data.status === "malicious";
    const statusLabel = isMalicious ? "MALICIOUS" : "SUSPICIOUS";
    const cardClass = isMalicious ? "card-malicious" : "card-suspicious";
    const tagClass = isMalicious ? "tag-malicious" : "tag-suspicious";
    const reasonClass = isMalicious ? "" : "reason-suspicious";
    const icon = isMalicious ? "🛑" : "⚠️";

    let domainName = "Unknown Domain";
    try {
      domainName = new URL(data.url).hostname;
    } catch (e) {}

    const sourcesList = data.sources && data.sources.length > 0 ? data.sources.join(", ") : "Security Reputation Engine";

    const overlay = document.createElement("div");
    overlay.id = "phishing-guard-modal-overlay";

    overlay.innerHTML = `
      <div class="pg-modal-card ${cardClass}" role="dialog" aria-modal="true">
        <div class="pg-modal-header">
          <div class="pg-modal-icon">${icon}</div>
          <div>
            <h2 class="pg-modal-title">Security Warning: Dangerous Link Blocked</h2>
            <div class="pg-modal-subtitle">Phishing & Malicious Link Alert intercepted this navigation</div>
          </div>
        </div>

        <div style="margin: 10px 0;">
          <span class="pg-threat-tag ${tagClass}">${escapeHtml(statusLabel)}</span>
          <span style="font-size:12px; color:#94a3b8; margin-left:8px;">Detected by: ${escapeHtml(sourcesList)}</span>
        </div>

        <div class="pg-modal-body">
          <p style="margin: 6px 0;">You clicked a link leading to a flagged destination:</p>
          <div class="pg-url-preview">${escapeHtml(data.url)}</div>

          <div class="pg-modal-reason ${reasonClass}">
            <strong>Threat Reason:</strong> ${escapeHtml(data.reason)}
          </div>

          <p style="font-size: 13px; color:#94a3b8; margin: 10px 0 0 0;">
            Phishing websites often impersonate legitimate services (like banks, email, or social networks) to steal your passwords or personal data.
          </p>
        </div>

        <div class="pg-modal-actions">
          <button id="pg-btn-back" class="pg-btn pg-btn-safe">
            🛡️ Stay Safe (Go Back)
          </button>
          <button id="pg-btn-proceed" class="pg-btn pg-btn-proceed">
            Proceed Anyway (Unsafe)
          </button>
          <button id="pg-btn-details" class="pg-btn pg-btn-proceed" style="border-style:dashed;">
            Full Warning Page ↗
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    // Button event listeners
    const backBtn = overlay.querySelector("#pg-btn-back");
    const proceedBtn = overlay.querySelector("#pg-btn-proceed");
    const detailsBtn = overlay.querySelector("#pg-btn-details");

    backBtn.addEventListener("click", () => {
      overlay.remove();
    });

    proceedBtn.addEventListener("click", () => {
      overlay.remove();
      // Allow user to navigate explicitly
      window.location.href = data.url;
    });

    detailsBtn.addEventListener("click", () => {
      overlay.remove();
      chrome.runtime.sendMessage({
        action: "OPEN_WARNING_PAGE",
        url: data.url,
        status: data.status,
        threat_type: data.threat_type,
        reason: data.reason,
        sources: data.sources
      });
    });
  }

  /**
   * Debounced scan trigger for initial load and MutationObserver.
   */
  function triggerScan() {
    if (scanDebounceTimer) clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(() => {
      scanWebpageLinks();
    }, 400);
  }

  // 1. Initial Page Scan
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", triggerScan);
  } else {
    triggerScan();
  }

  // 2. Dynamic DOM Mutation Observer (detects AJAX / infinite-scrolling links)
  const observer = new MutationObserver((mutations) => {
    let hasNewLinks = false;
    for (const m of mutations) {
      if (m.type === "childList" && m.addedNodes.length > 0) {
        for (const node of m.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) {
            if (node.tagName === "A" || node.querySelector("a[href]")) {
              hasNewLinks = true;
              break;
            }
          }
        }
      }
      if (hasNewLinks) break;
    }

    if (hasNewLinks) {
      triggerScan();
    }
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    window.addEventListener("DOMContentLoaded", () => {
      observer.observe(document.body, { childList: true, subtree: true });
    });
  }
})();
