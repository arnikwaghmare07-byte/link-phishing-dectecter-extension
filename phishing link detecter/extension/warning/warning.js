/**
 * Warning Page Script
 * Reads threat parameters from query string and handles user choice.
 */

document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "Unknown URL";
  const status = (params.get("status") || "malicious").toLowerCase();
  const reason = params.get("reason") || "Potential security hazard detected.";
  const threatType = params.get("threat_type") || "Threat Detected";
  
  let sources = [];
  try {
    sources = JSON.parse(params.get("sources") || "[]");
  } catch (e) {
    sources = [params.get("sources") || "Reputation Engine"];
  }

  // Update DOM elements
  const targetUrlEl = document.getElementById("targetUrl");
  const threatReasonEl = document.getElementById("threatReason");
  const securitySourcesEl = document.getElementById("securitySources");
  const threatBadge = document.getElementById("threatBadge");
  const shieldIcon = document.getElementById("shieldIcon");
  const warningCard = document.getElementById("warningCard");
  const pageHeading = document.getElementById("pageHeading");

  targetUrlEl.textContent = targetUrl;
  threatReasonEl.textContent = `${threatType}: ${reason}`;
  securitySourcesEl.textContent = sources.length > 0 ? sources.join(", ") : "Multi-source Reputation Engine";

  if (status === "suspicious") {
    threatBadge.textContent = "SUSPICIOUS";
    threatBadge.className = "badge badge-suspicious";
    shieldIcon.textContent = "⚠️";
    warningCard.className = "warning-container suspicious-border";
    threatReasonEl.className = "detail-value reason-box suspicious-reason";
    pageHeading.textContent = "Security Warning: Suspicious Link Detected";
  } else {
    threatBadge.textContent = "MALICIOUS";
    threatBadge.className = "badge badge-malicious";
    shieldIcon.textContent = "🛑";
  }

  // Button actions
  const goBackBtn = document.getElementById("goBackBtn");
  const proceedBtn = document.getElementById("proceedBtn");

  goBackBtn.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  proceedBtn.addEventListener("click", () => {
    if (targetUrl && targetUrl !== "Unknown URL") {
      window.location.href = targetUrl;
    }
  });
});
