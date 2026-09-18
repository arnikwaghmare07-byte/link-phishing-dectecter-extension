# Phishing & Malicious Link Alert — Chrome Extension (Manifest V3)

This folder contains the complete, uncompiled Chrome Extension built with **Manifest V3**, modern HTML5, CSS3, and Vanilla JavaScript.

---

## 🚀 How to Load in Google Chrome

1. Open **Google Chrome**.
2. In the URL bar, navigate to: `chrome://extensions`.
3. Enable **Developer mode** using the toggle in the top-right corner.
4. Click the **"Load unpacked"** button in the top-left corner.
5. Select this `extension` folder (`.../phishing-link-alert/extension`).
6. Click the puzzle icon in Chrome's toolbar and **Pin** the "Phishing & Malicious Link Alert" extension.

---

## 📂 Folder Structure

```
extension/
├── manifest.json            # Manifest V3 extension configuration and permissions
├── background/
│   └── service-worker.js    # Background event broker, caching, and tab statistics
├── content/
│   ├── content.js           # Injects into webpages, scans links, handles interception
│   └── content.css          # Visual highlighting, hover tooltips, and modal styles
├── popup/
│   ├── popup.html           # Toolbar popup interface
│   ├── popup.css            # Popup styling
│   └── popup.js             # Statistics controller and user settings
├── warning/
│   ├── warning.html         # Full standalone warning screen
│   ├── warning.css          # Warning screen styling
│   └── warning.js           # Warning screen decision handler
└── icons/
    ├── icon16.png           # 16x16 toolbar icon
    ├── icon48.png           # 48x48 extensions manager icon
    └── icon128.png          # 128x128 store & installation icon
```

---

## 🎓 Manifest V3 Permissions Explained (For Viva)

| Permission | Purpose & Rationale |
| :--- | :--- |
| `storage` | Saves user settings (protection toggle, demo mode) and caches scanned link reputations locally in `chrome.storage.local`. |
| `activeTab` | Grants temporary, secure access to the active tab's domain name when the user clicks the extension icon, without requesting broad invasive browser history permissions. |
| `host_permissions: http://localhost:5000/*` | Allows the background service worker to communicate with the local Python Flask reputation server. |
| `host_permissions: http://*/*, https://*/*` | Enables the content script to scan hyperlinks on regular web pages visited by the user. |

---

## ⚡ Key Technical Features

1. **Pre-Click Interception**: Uses `addEventListener('click', handler, true)` (capture phase) to intercept clicks before any page navigation or JavaScript redirection can happen.
2. **MutationObserver**: Continuously observes `document.body` to automatically detect links added dynamically by JavaScript, infinite scrolling, or AJAX requests.
3. **Privacy-First**: No form inputs, passwords, or personal data are ever read or transmitted. Only link URLs are sent for threat reputation verification.
