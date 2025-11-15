#!/usr/bin/env python3
"""
main.py — CYbersesc Orchestrator (Realtime DB caching, single user input)

Features:
 - Only asks for the URL to check
 - Uses firebase_client.py for Realtime Database
 - Checks if URL was analyzed in the past 7 hours
 - Fetches from Firebase if cached, or runs full analysis otherwise
"""

import os
import sys
import json
from datetime import datetime, timedelta
import requests
from typing import Any, Dict, List

# ---------------------------------------------------------------------
# Ensure local imports work
# ---------------------------------------------------------------------
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------
# Import local modules
# ---------------------------------------------------------------------
from ExtractingLinks import extract_links
from VirusTotalUrlChecker import virus_total
from redirect_chain import redirect_chain
from deceptive_characters import check as deceptive_check
from domain_age import dom_age
import firebase_client as fb

# ---------------------------------------------------------------------
# 🔧 Firebase configuration (set these ONCE)
# ---------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# By default look for the file in the same folder as this script:
SERVICE_ACCOUNT_PATH = os.path.join(BASE_DIR, "serviceAccountKey.json")
# Replace the DB URL below with your project's Realtime DB URL if different
REALTIME_DB_URL = "https://urlcheckercybersec-default-rtdb.asia-southeast1.firebasedatabase.app"

# ---------------------------------------------------------------------
USER_AGENT = {"User-Agent": "cybersesc-link-checker/2.0"}

# ---------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------
def fetch_page(url: str, timeout: int = 12):
    """Fetch page content and return (html, final_url_after_redirects)."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    resp = requests.get(url, timeout=timeout, headers=USER_AGENT)
    resp.raise_for_status()
    return resp.text, resp.url


def safe_virustotal_check(url: str) -> Dict[str, Any]:
    """Call the VirusTotal checker safely and capture exceptions."""
    try:
        return virus_total(url)
    except Exception as e:
        return {"error": f"VirusTotal check failed: {e}"}


def compute_domain_age_years(dom_age_result):
    """Normalize domain_age result to a float in years when possible."""
    try:
        if hasattr(dom_age_result, "days"):
            return round(dom_age_result.days / 365.25, 2)
    except Exception:
        pass
    return dom_age_result


# ---------------------------------------------------------------------
# Build report
# ---------------------------------------------------------------------
def build_report(target_url: str) -> Dict[str, Any]:
    now = datetime.utcnow()
    report = {
        "target": target_url,
        "timestamp": now.isoformat() + "Z",
        "domain_age": None,
        "deceptive_characters": None,
        "redirect_chain": None,
        "link_extraction": [],
        "virustotal": {},
        "notes": [],
    }

    # Domain age
    try:
        report["domain_age"] = compute_domain_age_years(dom_age(target_url))
    except Exception as e:
        report["domain_age"] = f"error: {e}"

    # Deceptive / punycode
    try:
        report["deceptive_characters"] = deceptive_check(target_url)
    except Exception as e:
        report["deceptive_characters"] = f"error: {e}"

    # Redirect chain
    try:
        report["redirect_chain"] = redirect_chain(target_url)
    except Exception as e:
        report["redirect_chain"] = f"error: {e}"

    # Links
    try:
        html, final_url = fetch_page(target_url)
        links = extract_links(html, final_url)
        report["link_extraction"] = links or []
    except Exception as e:
        report["link_extraction"] = []
        report["notes"].append(f"Failed to fetch or extract links: {e}")

    # VirusTotal (optional)
    for link in report["link_extraction"]:
        report["virustotal"][link] = safe_virustotal_check(link)

    return report


# ---------------------------------------------------------------------
# Simple scoring logic
# ---------------------------------------------------------------------
def generate_final_assessment(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce an assessment that includes individual scores for each test plus a combined score.
    Returns a dict:
      {
        "individual_scores": {
            "domain_age": 0-100,
            "deception": 0-100,
            "redirect_chain": 0-100,
            "links": 0-100,
            "virustotal": 0-100
        },
        "metrics": {...},            # numeric helpers and counts
        "rationale": [...],         # human-friendly reasons
        "score": combined_score,    # final weighted score (0-100)
        "verdict": "Good|Caution|Suspicious|Malicious"
      }
    """
    rationale = []
    metrics: Dict[str, Any] = {}

    # --- Domain age score (0-100) ---
    domain_age_val = report.get("domain_age")
    # default if unknown
    if isinstance(domain_age_val, (int, float)):
        da = float(domain_age_val)
        if da >= 5.0:
            domain_age_score = 100
            rationale.append(f"Domain age: {da} years — strong positive signal.")
        elif da >= 1.0:
            domain_age_score = 70
            rationale.append(f"Domain age: {da} years — moderately positive.")
        elif da >= 0.2:
            domain_age_score = 40
            rationale.append(f"Domain age: {da} years — slightly new.")
        else:
            domain_age_score = 10
            rationale.append(f"Domain age: {da} years — very new (suspicious).")
    else:
        # attempt to parse timedelta object returned by dom_age()
        try:
            # some implementations return a datetime.timedelta
            if hasattr(domain_age_val, "days"):
                days = float(getattr(domain_age_val, "days"))
                years = round(days / 365.25, 2)
                domain_age_val = years
                if years >= 5.0:
                    domain_age_score = 100
                    rationale.append(f"Domain age: {years} years — strong positive signal.")
                elif years >= 1.0:
                    domain_age_score = 70
                    rationale.append(f"Domain age: {years} years — moderately positive.")
                elif years >= 0.2:
                    domain_age_score = 40
                    rationale.append(f"Domain age: {years} years — slightly new.")
                else:
                    domain_age_score = 10
                    rationale.append(f"Domain age: {years} years — very new (suspicious).")
            else:
                domain_age_score = 50
                rationale.append(f"Domain age unavailable: {domain_age_val}")
        except Exception:
            domain_age_score = 50
            rationale.append(f"Domain age unavailable or error: {domain_age_val}")

    metrics["domain_age_value"] = domain_age_val
    metrics["domain_age_score"] = domain_age_score

    # --- Deceptive / punycode score (0 or 100) ---
    deceptive = report.get("deceptive_characters")
    deception_flag = False
    try:
        if isinstance(deceptive, dict):
            deception_flag = bool(deceptive.get("has_deceptive", False))
        elif isinstance(deceptive, bool):
            deception_flag = deceptive
        elif isinstance(deceptive, str):
            deception_flag = deceptive.lower() in ("true", "yes", "1")
    except Exception:
        deception_flag = False

    deception_score = 0 if deception_flag else 100
    if deception_flag:
        rationale.append("Deceptive/punycode characters detected — high spoofing risk.")
    else:
        rationale.append("No deceptive/punycode characters detected.")
    metrics["deception_flag"] = deception_flag
    metrics["deception_score"] = deception_score

    # --- Redirect chain score (based on length) ---
    rc = report.get("redirect_chain")
    rc_len = None
    try:
        if isinstance(rc, list):
            rc_len = len(rc)
        elif isinstance(rc, tuple):
            rc_len = 1
        elif isinstance(rc, str):
            rc_len = 1
    except Exception:
        rc_len = None

    if rc_len is None:
        redirect_chain_score = 50
        rationale.append(f"Redirect chain info unavailable: {rc}")
    else:
        if rc_len <= 1:
            redirect_chain_score = 100
            rationale.append("Redirect chain short or absent.")
        elif rc_len <= 3:
            redirect_chain_score = 70
            rationale.append(f"Redirect chain length {rc_len} — acceptable.")
        else:
            redirect_chain_score = 20
            rationale.append(f"Redirect chain length {rc_len} — suspicious (long chain).")

    metrics["redirect_chain_length"] = rc_len
    metrics["redirect_chain_score"] = redirect_chain_score

    # --- Links profile score (internal vs external ratio) ---
    links = report.get("link_extraction", []) or []
    total_links = len(links)
    metrics["total_links"] = total_links
    external_links = 0
    target_domain = ""
    try:
        target_domain = report.get("target", "") or ""
    except Exception:
        target_domain = ""

    for l in links:
        try:
            # treat as external if target domain not a substring of the link
            if target_domain and (target_domain not in l):
                external_links += 1
        except Exception:
            continue

    metrics["external_links"] = external_links

    if total_links == 0:
        link_score = 80
        rationale.append("No links found on page (neutral).")
    else:
        ratio_external = external_links / total_links
        # compute bucketed score
        if ratio_external < 0.2:
            link_score = 90
            rationale.append(f"{total_links} links found, mostly internal ({external_links} external).")
        elif ratio_external < 0.6:
            link_score = 60
            rationale.append(f"{total_links} links found; moderate external links ({external_links}).")
        else:
            link_score = 20
            rationale.append(f"{total_links} links and majority external ({external_links}) — suspicious.")
    metrics["link_score"] = link_score
    metrics["external_ratio"] = (external_links / total_links) if total_links else None

    # --- VirusTotal summarization score ---
    vt = report.get("virustotal", {}) or {}
    vt_total_checked = 0
    vt_malicious_count = 0
    vt_suspicious_count = 0

    # vt may be a dict mapping link -> result
    if isinstance(vt, dict):
        for link, res in vt.items():
            vt_total_checked += 1
            # common shapes: res.get("stats") or res.get("positives")
            try:
                if isinstance(res, dict):
                    stats = res.get("stats") or res.get("last_analysis_stats") or {}
                    # some vt wrappers use keys like 'malicious', 'suspicious'
                    if isinstance(stats, dict):
                        if stats.get("malicious", 0) > 0:
                            vt_malicious_count += 1
                        elif stats.get("suspicious", 0) > 0:
                            vt_suspicious_count += 1
                    # fallback: look for positives key
                    elif isinstance(res.get("positives"), (int, float)) and res.get("positives", 0) > 0:
                        vt_suspicious_count += 1
            except Exception:
                continue

    # metrics
    metrics["vt_total_checked"] = vt_total_checked
    metrics["vt_malicious"] = vt_malicious_count
    metrics["vt_suspicious"] = vt_suspicious_count

    # score mapping
    if vt_total_checked == 0:
        vt_score = 80
        rationale.append("No VirusTotal checks performed (or no links to check).")
    else:
        if vt_malicious_count > 0:
            vt_score = 0
            rationale.append(f"VirusTotal: {vt_malicious_count}/{vt_total_checked} links flagged malicious.")
        elif vt_suspicious_count > 0:
            vt_score = 30
            rationale.append(f"VirusTotal: {vt_suspicious_count}/{vt_total_checked} links flagged suspicious.")
        else:
            vt_score = 100
            rationale.append("VirusTotal: no engines flagged the checked links.")
    metrics["vt_score"] = vt_score

    # --- Combine scores using weights ---
    weights = {
        "domain_age": 0.15,
        "deception": 0.25,
        "redirect_chain": 0.15,
        "links": 0.15,
        "virustotal": 0.30,
    }

    # ensure numeric values
    domain_age_score = float(domain_age_score)
    deception_score = float(deception_score)
    redirect_chain_score = float(redirect_chain_score)
    link_score = float(link_score)
    vt_score = float(vt_score)

    combined = (
        domain_age_score * weights["domain_age"]
        + deception_score * weights["deception"]
        + redirect_chain_score * weights["redirect_chain"]
        + link_score * weights["links"]
        + vt_score * weights["virustotal"]
    )

    # round combined score to 2 decimal places
    score = round(combined, 2)

    # verdict thresholds
    if score >= 80:
        verdict = "Good"
    elif score >= 50:
        verdict = "Caution"
    elif score >= 20:
        verdict = "Suspicious"
    else:
        verdict = "Malicious"

    individual_scores = {
        "domain_age": int(domain_age_score),
        "deception": int(deception_score),
        "redirect_chain": int(redirect_chain_score),
        "links": int(link_score),
        "virustotal": int(vt_score),
    }

    assessment = {
        "individual_scores": individual_scores,
        "metrics": metrics,
        "rationale": rationale,
        "score": score,
        "verdict": verdict,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    return assessment



# ---------------------------------------------------------------------
# Firebase helpers
# ---------------------------------------------------------------------
def find_recent_report(target_url: str, max_age_hours: int = 7):
    """Check if a report for this URL exists and is recent (< max_age_hours)."""
    try:
        data = fb.list_reports("/url_reports", limit=100)
    except Exception as e:
        print(f"[firebase] list_reports error: {e}")
        return None

    if not data:
        return None

    for key, report in data.items():
        if report.get("target") == target_url:
            try:
                ts = datetime.fromisoformat(report["timestamp"].replace("Z", ""))
                if datetime.utcnow() - ts <= timedelta(hours=max_age_hours):
                    report["_firebase_key"] = key
                    return report
            except Exception:
                continue
    return None


# ---------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------
def main():
    # ensure service account file exists
    if not os.path.isfile(SERVICE_ACCOUNT_PATH):
        print(f"❌ service account file not found at: {SERVICE_ACCOUNT_PATH}")
        print("   Put your downloaded service account JSON into the script folder, or set SERVICE_ACCOUNT_PATH to the correct absolute path.")
        return

    # init firebase with explicit keywords (match firebase_client signature)
    try:
        fb.init_firebase(
            service_account_path=SERVICE_ACCOUNT_PATH,
            use_realtime=True,
            realtime_db_url=REALTIME_DB_URL,
        )
    except TypeError:
        # fallback if firebase_client has simpler signature (service_account_path, realtime_db_url)
        try:
            fb.init_firebase(SERVICE_ACCOUNT_PATH, REALTIME_DB_URL)
        except Exception as e:
            print(f"Failed to initialize Firebase (fallback): {e}")
            return
    except Exception as e:
        print(f"Failed to initialize Firebase: {e}")
        return

    # Ask user for the URL
    target = input("🔗 Enter the URL you want to analyze: ").strip()
    if not target:
        print("❌ No URL entered. Exiting.")
        return

    print(f"\n[{datetime.utcnow().isoformat()}] 🔍 Checking {target}")

    # Check if already analyzed in last 7 hours
    existing = find_recent_report(target)
    if existing:
        print("\n⚡ Found recent report in database (within 7 hrs). Skipping re-analysis.\n")
        print(json.dumps(existing, indent=2))
        return

    # Run full analysis
    print("\n🧠 Running full analysis...")
    report = build_report(target)
    report["final_assessment"] = generate_final_assessment(report)

    # Push to Firebase
    try:
        key = fb.push_report(report)
        report["_firebase_key"] = key
    except Exception as e:
        print(f"[firebase] push_report failed: {e}")

    print("\n✅ Report uploaded successfully.")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
