# 🛡️ Phishing URL Detection Tool

A Python-based command-line tool that analyzes URLs through **5 independent security checks** to determine whether a site is likely a phishing attempt — and logs malicious results for future reference.

## 🔍 Features

- **Domain Age Check** — Uses WHOIS lookups to flag recently registered domains, a common trait of phishing sites.
- **Reputation Check** — Cross-references the URL against the [VirusTotal API](https://www.virustotal.com/) to check for known malicious activity.
- **Deceptive Character Check** — Detects typosquatting and homograph attacks (e.g., `paypa1.com` mimicking `paypal.com`).
- **Link Extraction** — Extracts and analyzes embedded links on the target page for suspicious patterns.
- **Redirection Chain Analysis** — Traces every hop a URL makes to expose hidden or obfuscated redirects.
- **Malicious Site Logging** — Automatically saves flagged URLs to a local database, avoiding redundant re-scanning and building a growing blocklist over time.

## 🧰 Tech Stack

- **Language:** Python
- **APIs:** VirusTotal API, WHOIS
- **Storage:** firebase
- **Libraries:** os, sys, json, datetime, timedelta, requests, urlib.parse, whois, firebase_admin

## ⚙️ How It Works

1. User inputs a URL via the command line.
2. The tool runs all 5 checks sequentially.
3. Each check returns a risk signal (pass/fail or risk score).
4. Signals are combined to produce an overall verdict — **Safe** or **Phishing Detected**.
5. If flagged as malicious, the URL is saved to the database for faster detection on future scans.

## ▶️ Usage

Run the script from the command line and enter a URL when prompted:

```bash
python phishing_detector.py
```
