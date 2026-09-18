# Phishing & Malicious Link Alert Browser Extension

> **Diploma in Computer Science & Engineering (CSE) Final Year Project**  
> A lightweight, real-time cybersecurity browser extension (Manifest V3) paired with a Python Flask threat reputation backend to protect users from phishing attacks, malware downloads, and fraudulent websites.

---

## 📋 Table of Contents
1. [Project Overview](#-project-overview)
2. [Problem Statement & Objectives](#-problem-statement--objectives)
3. [Key Features](#-key-features)
4. [System Architecture](#-system-architecture)
5. [Technology Stack & Rationale](#-technology-stack--rationale)
6. [Project File Structure](#-project-file-structure)
7. [How the System Works (Lifecycle Flow)](#-how-the-system-works-lifecycle-flow)
8. [Multi-Source Threat Decision Module](#-multi-source-threat-decision-module)
9. [Installation & Setup Guide](#-installation--setup-guide)
10. [How to Run Live Demonstration (For Teachers & Examiners)](#-how-to-run-live-demonstration-for-teachers--examiners)
11. [Configuring Live External Security APIs](#-configuring-live-external-security-apis)
12. [Privacy & Security Considerations](#-privacy--security-considerations)
13. [Limitations & Future Scope](#-limitations--future-scope)
14. [🎓 HOW TO EXPLAIN THIS PROJECT TO YOUR TEACHER (Viva Guide in English + Hinglish)](#-how-to-explain-this-project-to-your-teacher-viva-guide)

---

## 🛡️ Project Overview

Cybercriminals frequently use deceptive hyperlinks distributed through social networks, spam emails, and fraudulent websites to redirect unsuspecting users to phishing pages that steal bank details, credentials, or deploy malware.

The **Phishing & Malicious Link Alert Browser Extension** automatically scans hyperlinks on every webpage a user visits. It verifies their reputation using a dedicated Python Flask backend integrating with **Google Safe Browsing API**, **VirusTotal API**, and a **Heuristic Simulation Engine**. 

Dangerous links are visually outlined on the webpage, and if a user accidentally clicks a malicious link, navigation is **immediately intercepted before the browser can navigate**, displaying an interactive warning modal.

---

## 🎯 Problem Statement & Objectives

### Problem Statement
Standard internet users cannot easily differentiate between a legitimate URL (`paypal.com`) and a deceptive homograph or phishing URL (`paypal-secure-login-fake.com`). Most modern browsers only block known phishing domains *after* navigation has already started or completed.

### Objectives
1. **Real-time Link Scanning**: Detect all hyperlinks on visited web pages without noticeable browser slowdown.
2. **Multi-Source Reputation Checking**: Aggregate security intelligence from Google Safe Browsing and VirusTotal.
3. **Visual Threat Indicators**: Outline dangerous links (Red for Malicious, Amber for Suspicious) with informational tooltips.
4. **Pre-Click Interception**: Block the click in the browser's DOM event capture phase *before* navigation occurs.
5. **Zero-API Demo Mode**: Provide built-in simulation for college presentations and lab evaluations without requiring credit cards or paid API quotas.
6. **Student-Friendly Codebase**: Clean, modular architecture separating Chrome Extension frontend from the Python backend.

---

## ✨ Key Features

- **Manifest V3 Compliant**: Built strictly on Google Chrome's latest extension standard using Service Workers.
- **Pre-Click Protection**: Stops navigation before the destination page can load malicious scripts or harvest credentials.
- **Dynamic Link Detection**: Leverages JavaScript `MutationObserver` to scan links added dynamically by infinite scrolling or AJAX feeds.
- **Dual-Layer Caching (RAM + SQLite)**: Memorizes scanned URLs in memory and SQLite (`scans.db`) with configurable 24-hour TTL, slashing latency to < 15ms.
- **Secure API Proxy Architecture**: Third-party API keys remain safely stored on the Python server and are **never** exposed to client-side scripts.
- **Interactive Popup Dashboard**: Displays live counts of Safe, Suspicious, Malicious, and Unknown links on the current tab.
- **Zero-Setup Demo Mode**: Ready for teacher evaluation immediately with realistic simulated attack patterns.

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    User([User Visits Webpage]) --> Chrome[Google Chrome Browser]
    Chrome --> CS[Content Script: content.js]
    CS -->|1. Extract & Normalize Links| Dedupe[URL Deduplication & Batching]
    Dedupe -->|2. chrome.runtime.sendMessage| BG[Background Service Worker: service-worker.js]
    BG -->|3. POST /api/check-urls| Backend[Python Flask Server: app.py]

    subgraph Backend [Python Flask Backend :5000]
        Backend --> Cache[(Cache: Memory + SQLite)]
        Cache -->|Cache Miss| Classifier[Threat Classifier: threat_classifier.py]
        Classifier --> GSB[Google Safe Browsing v4 API]
        Classifier --> VT[VirusTotal v3 API]
        Classifier --> DemoEngine[Demo / Heuristic Engine]
        GSB --> Classifier
        VT --> Classifier
        DemoEngine --> Classifier
        Classifier -->|Save Verdict| Cache
    end

    Backend -->|4. Return Threat Verdicts| BG
    BG -->|5. Update Tab Stats & Badge| Popup[Extension Popup UI: popup.html]
    BG -->|6. Send Results| CS
    CS -->|7. Apply CSS Classes| DomLinks[Webpage Hyperlinks]

    DomLinks -->|Hover| Tooltip[Threat Hover Tooltip]
    DomLinks -->|Click Malicious Link| Intercept{Pre-Click Interception}
    Intercept -->|Prevent Navigation| WarningModal[In-Page Warning Modal / warning.html]
    WarningModal -->|Option 1: Go Back| SafeExit[Stay on Current Webpage]
    WarningModal -->|Option 2: Proceed Anyway| Destination[Navigate to Website]
```

---

## 🧰 Technology Stack & Rationale

| Component | Technology | Rationale / Viva Defense |
| :--- | :--- | :--- |
| **Frontend / Extension** | HTML5, CSS3, Vanilla JS | Lightweight, no heavy external dependencies or bundlers needed, easy for teachers to inspect. |
| **Extension Standard** | Chrome Manifest V3 | Latest Google Chrome specification requiring Service Workers and enhanced security. |
| **Backend Framework** | Python 3 + Flask | Python is the industry standard for cybersecurity tools; Flask provides a clean, minimal REST API. |
| **Network & CORS** | `requests`, `flask-cors` | Handles asynchronous external API queries and Cross-Origin requests from the extension. |
| **Database & Cache** | SQLite + In-Memory Dict | Zero configuration needed; stores scan history locally without complex database setups. |
| **Security APIs** | Google Safe Browsing & VirusTotal | Industry-standard threat intelligence services aggregating feeds from 70+ antivirus engines. |

---

## 📂 Project File Structure

```
phishing-link-alert/
│
├── extension/                       # Google Chrome Extension (Manifest V3)
│   ├── manifest.json                # Extension metadata and permission definitions
│   ├── background/
│   │   └── service-worker.js        # Background event coordinator, badge manager, caching
│   ├── content/
│   │   ├── content.js               # Webpage link scanner, pre-click interceptor, DOM modal
│   │   └── content.css              # Visual outline highlights, danger badges, modal styles
│   ├── popup/
│   │   ├── popup.html               # Toolbar popup user interface
│   │   ├── popup.css                # Card-based modern dark UI styling
│   │   └── popup.js                 # Popup controller and preference synchronizer
│   ├── warning/
│   │   ├── warning.html             # Standalone full-page warning screen
│   │   ├── warning.css              # Warning screen layout & styles
│   │   └── warning.js               # Warning page decision controller
│   ├── icons/                       # Extension icon assets (16x16, 48x48, 128x128)
│   └── README.md                    # Quick guide for loading the extension
│
├── backend/                         # Python Flask Threat Reputation Backend
│   ├── app.py                       # RESTful API server & demo endpoints
│   ├── url_checker.py               # URL canonicalization, API integration, Demo matcher
│   ├── threat_classifier.py         # Multi-source decision aggregation module
│   ├── cache.py                     # Dual-layer in-memory & SQLite cache
│   ├── database.py                  # SQLite database connection & scan log storage
│   ├── requirements.txt             # Python dependencies (Flask, requests, etc.)
│   ├── .env.example                 # Environment configuration template
│   └── .env                         # Active configuration file
│
├── tests/                           # Unit Verification Test Suite
│   ├── test_url_checker.py          # Tests for normalization, schemes, and deduplication
│   └── test_classifier.py           # Tests for threat matrix decisions & failure fallbacks
│
├── test-page.html                   # College demonstration & examiner evaluation page
└── README.md                        # Master project documentation
```

---

## 🔄 How the System Works (Lifecycle Flow)

1. **Page Load**: When the user opens any webpage, `content.js` executes at `document_idle`.
2. **Link Extraction**: The script queries all `a[href]` tags, filtering out non-navigational protocols (`javascript:`, `mailto:`, `#anchors`).
3. **URL Normalization**: URLs are converted to absolute format, lowercased, and query/path fragments sanitized.
4. **Deduplication & Batching**: Unique URLs are batched and sent via `chrome.runtime.sendMessage` to `service-worker.js`.
5. **Backend Verification**: The service worker sends `POST /api/check-urls` to the Flask backend on `http://localhost:5000`.
6. **Cache Check**: Backend checks memory cache and SQLite (`scans.db`). If unvisited, it queries Google Safe Browsing, VirusTotal, or the Demo Engine.
7. **Decision Aggregation**: The `ThreatClassifier` evaluates signals and assigns one of 4 statuses:
   - `SAFE`: Zero security vendors report threats (*"No threat detected by available sources"*).
   - `SUSPICIOUS`: Flagged by 1 antivirus vendor or matches suspicious patterns (*Amber dashed outline*).
   - `MALICIOUS`: Flagged by Google Safe Browsing or >= 2 antivirus vendors (*Red solid outline + 🛑*).
   - `UNKNOWN`: APIs unreachable, timed out, or quota exceeded (*Neutral*).
8. **Visual Highlighting**: The content script applies CSS classes `.phishing-danger` or `.suspicious-link`.
9. **Pre-Click Interception**: When a user clicks a flagged link:
   - The capture-phase listener captures the click before default navigation occurs.
   - `e.preventDefault()` halts browser navigation.
   - An interactive in-page warning modal appears giving explicit choices: `[ Stay Safe (Go Back) ]` or `[ Proceed Anyway ]`.

---

## ⚖️ Multi-Source Threat Decision Module

The project implements a structured decision matrix in `backend/threat_classifier.py`:

```
+------------------------------------+---------------------------------------+-------------------+
| Google Safe Browsing               | VirusTotal API                        | Final Verdict     |
+------------------------------------+---------------------------------------+-------------------+
| SOCIAL_ENGINEERING (Phishing)      | Any                                   | MALICIOUS         |
| MALWARE / UNWANTED_SOFTWARE        | Any                                   | MALICIOUS         |
| Clean (No Threat)                  | >= 2 Antivirus Engines Flag Malicious | MALICIOUS         |
| Clean (No Threat)                  | 1 Engine Malicious OR >=1 Suspicious  | SUSPICIOUS        |
| Clean (No Threat)                  | 0 Engines Flagged                     | SAFE              |
| Service Offline / Quota Exceeded   | Service Offline / Quota Exceeded      | UNKNOWN           |
+------------------------------------+---------------------------------------+-------------------+
```

> [!IMPORTANT]
> **Ethical Security Principle**: When external security APIs are offline or time out, the system **never** marks the URL as "SAFE". It assigns `UNKNOWN` ("Unable to verify link reputation").

---

## 💻 Installation & Setup Guide

### Step 1: Clone or Navigate to the Project Folder
Open PowerShell or Command Prompt:
```powershell
cd "D:\phishing link detecter"
```

### Step 2: Set Up Python Backend
1. Check that Python is installed:
   ```powershell
   py --version
   ```
2. Install the lightweight dependencies:
   ```powershell
   py -m pip install -r backend\requirements.txt
   ```
3. Run backend unit tests to ensure everything is operating correctly:
   ```powershell
   py -m unittest discover -s tests -v
   ```
   *(All 11 tests will pass with `OK`)*

4. Start the Flask backend server:
   ```powershell
   py backend\app.py
   ```
   *You should see:*
   ```
   ============================================================
   🛡️  Phishing & Malicious Link Alert Backend Starting...
   📡  Listening on: http://localhost:5000
   ============================================================
   ```

---

### Step 3: Load the Extension into Google Chrome

1. Open **Google Chrome**.
2. Visit `chrome://extensions` in the address bar.
3. Enable **Developer mode** toggle in the top-right corner.
4. Click **Load unpacked** (top-left button).
5. Browse and select the `extension` folder:
   `D:\phishing link detecter\extension`
6. Click the extension puzzle icon on Chrome's toolbar and pin **Phishing Guard**.

---

## 🧪 How to Run Live Demonstration (For Teachers & Examiners)

We have provided a dedicated showcase file: `test-page.html`.

1. Double click or drag-and-drop `test-page.html` into Google Chrome (or navigate to `file:///D:/phishing%20link%20detecter/test-page.html`).
2. **Observe Automatic Highlighting**:
   - Safe links (`wikipedia.org`, `python.org`) appear normal.
   - Suspicious links receive an **amber dashed border** with a `⚠️` badge.
   - Malicious links (`malicious-example.test`, `paypal-secure-login-fake.com`) receive a **bright red border** with a `🛑` icon.
3. **Hover Tooltips**: Move your cursor over any flagged link to display the threat explanation tooltip.
4. **Pre-Click Interception Demonstration**:
   - Click on `https://malicious-example.test/fake-banking-login`.
   - The browser will **not** open the website.
   - The **In-Page Security Warning Modal** immediately appears on screen explaining the phishing threat.
   - Click **"🛡️ Stay Safe (Go Back)"** &mdash; the modal closes and your tab remains safe!
   - Click it again and choose **"Proceed Anyway"** &mdash; verifies user override capability.
5. **MutationObserver Live Test**:
   - Click the button **"➕ Inject Dynamic Links via JavaScript"**.
   - Notice how the newly injected link is detected and highlighted in real-time without refreshing the page!
6. **Popup Dashboard**:
   - Click the extension shield icon on the Chrome toolbar to inspect the real-time tab statistics counter (Safe, Suspicious, Malicious, Unknown).

---

## 🔑 Configuring Live External Security APIs

By default, **Demo Mode is enabled** so examiners can test all threat categories immediately without external API keys.

To enable live production queries against real internet databases:

1. Open `backend/.env` in any text editor.
2. Add your free API keys:
   ```ini
   # Google Safe Browsing v4 Key (from console.cloud.google.com)
   GOOGLE_SAFE_BROWSING_API_KEY=AIzaSyYourGoogleApiKeyHere...

   # VirusTotal v3 Key (from virustotal.com/gui/my-apikey)
   VIRUSTOTAL_API_KEY=your_virustotal_sha256_api_key...

   # Disable Demo Mode for pure live checking
   DEMO_MODE=False
   ```
3. Restart `backend/app.py`.

---

## 🔒 Privacy & Security Considerations

- **No Personal Data Stored**: The extension does **not** read form inputs, passwords, cookies, or browser history.
- **Backend Key Protection**: API keys are saved strictly in `backend/.env` on the server and are **never** bundled inside extension JavaScript files.
- **Secure Cross-Origin Communication**: Uses strictly typed JSON payloads with URL validation on both client and server sides.

---

## 🚀 Limitations & Future Scope

### Limitations
1. Zero-day phishing links created minutes earlier might not yet appear in global security databases.
2. Browser-internal URLs (`chrome://settings`) cannot be inspected due to Chrome security restrictions.

### Future Scope (Project Roadmap)
- **AI/ML Heuristics**: Train a machine learning model (e.g., Random Forest / LSTM) on lexical URL features (entropy, length, typo-squatting) for zero-hour phishing detection.
- **Cross-Browser Support**: Port to Firefox (WebExtensions API) and Microsoft Edge.
- **QR Code Scanner Integration**: Scan QR codes on web pages to verify target URL reputations.
- **Email Client Plugin**: Extend link reputation checking into Gmail and Outlook web interfaces.

---

## 🎓 How to Explain this Project to Your Teacher (Viva Guide)

*(Read this section carefully before your viva examination! Formatted in simple English + easy Hinglish explanations)*

---

### Q1. What is the core objective of your project?
**English Answer**:  
*"Our project is a real-time cybersecurity browser extension developed on Chrome Manifest V3 with a Python Flask backend. Its objective is to protect users from phishing attacks and malware by automatically detecting all links on a webpage, verifying their reputation through security services like Google Safe Browsing and VirusTotal, highlighting dangerous links, and intercepting clicks before harmful navigation occurs."*

**Hinglish Defense**:  
*"Sir/Ma'am, humara project ek Chrome Extension hai jo user ke webpage pe maujood sabhi links ko background mein scan karta hai. Agar koi link phishing ya malware link hoti hai, toh yeh use red highlight kar deta hai aur user agar galti se click kar de, toh browser ko navigate hone se pehle hi rok kar warning screen dikha deta hai."*

---

### Q2. Why did you use Chrome Manifest V3 instead of Manifest V2?
**English Answer**:  
*"Google officially deprecated Manifest V2 in favor of Manifest V3. Manifest V3 replaces persistent background pages with lightweight, event-driven Service Workers, improves browser performance, limits unnecessary permissions, and forbids executing remotely hosted code, making extensions significantly more secure."*

**Hinglish Defense**:  
*"Google ne Manifest V2 ko deprecate kar diya hai. Manifest V3 Google ka latest standard hai. Isme background page ki jagah Service Worker use hota hai jo tabhi chalta hai jab koi event trigger ho. Isse browser fast rehta hai aur security badhti hai."*

---

### Q3. Why do we need a Python Flask backend? Why not call Google Safe Browsing directly from JavaScript?
**English Answer**:  
*"Exposing third-party API keys (like Google Safe Browsing or VirusTotal) inside client-side JavaScript content scripts is a major security vulnerability, as anyone can inspect the source code in Chrome Developer Tools and steal the key. The Python Flask backend acts as a secure API proxy, protects secret environment variables, handles caching, and implements the multi-source decision module."*

**Hinglish Defense**:  
*"Agar hum API keys ko Chrome Extension ke JavaScript mein likh dete, toh koi bhi 'Inspect Element' karke humari secret keys chori kar sakta tha. Isliye humne Python Flask backend banaya jisme `.env` file mein keys safe rehti hain aur caching aur decision logic bhi server pe hota hai."*

---

### Q4. How does Pre-Click Interception work? How do you stop navigation before the page loads?
**English Answer**:  
*"We attach a click event listener to the `document` object using the DOM Event Capture Phase (`addEventListener('click', handler, true)`). Because the capture phase triggers before bubbling and default element actions, we detect if the clicked element is a flagged anchor (`a[href]`), invoke `event.preventDefault()` and `event.stopPropagation()` to cancel the navigation immediately, and render our custom warning modal."*

**Hinglish Defense**:  
*"Humne JavaScript mein event capture phase use kiya hai (`useCapture = true`). Jab bhi user click karta hai, toh link open hone se pehle humara listener trigger hota hai. Agar link malicious hai, toh hum `e.preventDefault()` call karke click ko turant block kar dete hain aur warning modal show kar dete hain."*

---

### Q5. How does the extension detect newly added links on dynamic websites (like Twitter or Facebook)?
**English Answer**:  
*"Modern Single Page Applications load new content dynamically using AJAX while scrolling. We implemented a `MutationObserver` on `document.body` that listens for DOM tree mutations (added nodes). When new anchors are detected, it debounces the request and triggers reputation scanning automatically."*

**Hinglish Defense**:  
*"Infinite scroll websites jaise Instagram ya Twitter pe naye links scroll karte waqt add hote hain. Iske liye humne `MutationObserver` API lagayi hai. Yeh DOM mein naye elements add hote hi unhe observe karta hai aur naye links ko bina page refresh kiye scan kar leta hai."*

---

### Q6. Why is caching implemented in your backend?
**English Answer**:  
*"Webpages often have dozens of duplicate links to the same domains (e.g., footers, navigation bars). Without caching, scanning a 100-link page would exhaust our API quotas and cause severe latency. We use a dual-layer cache (In-memory Python dictionary + SQLite database) with a 24-hour TTL. Memory cache returns results in under 1 millisecond, drastically reducing external API consumption."*

**Hinglish Defense**:  
*"Ek hi page pe ek domain ke 50 links ho sakte hain. Agar hum baar-baar API ko request bhejenge toh quota khatam ho jayega aur page slow ho jayega. Humne RAM aur SQLite mein caching lagayi hai taaki pehle se scanned URL ka result 1 millisecond mein mil jaye."*

---

### Q7. What happens if the internet goes down or the security APIs are unreachable?
**English Answer**:  
*"Following core cybersecurity design principles, the system will never falsely report an unverified link as 'SAFE'. Instead, it returns the status `UNKNOWN` with the explanation 'Unable to verify link reputation', advising caution without giving false assurance."*

**Hinglish Defense**:  
*"Agar API down ho ya internet na ho, toh humara system kabhi bhi link ko 'SAFE' nahi bolega. Yeh ek basic security rule hai. System status ko 'UNKNOWN' set karega aur user ko batayega ki is link ko verify nahi kiya ja saka."*

---

### Q8. What is the difference between SAFE, SUSPICIOUS, MALICIOUS, and UNKNOWN?
1. **SAFE**: Verified against security feeds; no threats reported by any engine (*"No threat detected by available sources"*).
2. **SUSPICIOUS**: 1 antivirus engine or heuristic keyword flags potential risk (*Amber outline*).
3. **MALICIOUS**: Google Safe Browsing or multiple antivirus engines confirm phishing/malware (*Red outline + pre-click block*).
4. **UNKNOWN**: Services timed out, unreachable, or non-web protocols (*Neutral state*).

---

## 👨‍💻 Project Authors & Academic Credits
- **Project Title**: Phishing & Malicious Link Alert Browser Extension
- **Specialization**: Computer Science & Engineering (Cybersecurity & Web Technologies)
- **Year of Submission**: Final Year Diploma Project
- **License**: MIT Open Source Educational License
