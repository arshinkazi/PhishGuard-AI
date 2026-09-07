"""
virustotal.py
--------------
Phase 6 — Optional VirusTotal Integration.

If a VIRUSTOTAL_API_KEY environment variable is set, this module submits
the URL to VirusTotal's public API v3 and returns a summary of how many
security vendors flag it, plus a simple reputation label. If no API key
is configured (the default for local/demo use), every function returns
`available: false` immediately -- no network call is attempted, and the
dashboard hides this panel instead of showing an error.

This is presented in the UI as a *secondary, third-party opinion*,
clearly separated from PhishGuard AI's own ML prediction -- the two are
never merged into a single score.
"""

from __future__ import annotations

import base64
import logging
import os

import requests

logger = logging.getLogger(__name__)

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_TIMEOUT_SECONDS = 8


def is_configured() -> bool:
    """Whether a VirusTotal API key is present in the environment."""
    return bool(os.environ.get("VIRUSTOTAL_API_KEY"))


def _url_id(url: str) -> str:
    """VirusTotal's URL identifier: unpadded base64url of the raw URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def get_reputation(url: str) -> dict:
    """Look up a URL's VirusTotal reputation.

    Returns a dict always containing `available: bool`. When True, it also
    carries `malicious`, `suspicious`, `harmless`, `undetected` vendor
    counts, `total_vendors`, and a `recommendation` string. When False, it
    carries a `reason` explaining why (no key configured, submission
    needed, network error, etc.).
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"available": False, "reason": "No VirusTotal API key configured on this server."}

    headers = {"x-apikey": api_key}
    lookup_url = f"{VT_API_BASE}/urls/{_url_id(url)}"

    try:
        resp = requests.get(lookup_url, headers=headers, timeout=VT_TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        logger.warning("VirusTotal request failed: %s", exc)
        return {"available": False, "reason": "Could not reach VirusTotal."}

    if resp.status_code == 404:
        # URL not yet analyzed by VT -- submit it for future lookups.
        try:
            requests.post(
                f"{VT_API_BASE}/urls",
                headers=headers,
                data={"url": url},
                timeout=VT_TIMEOUT_SECONDS,
            )
        except requests.RequestException:
            pass
        return {"available": False, "reason": "URL not yet analyzed by VirusTotal; it has been submitted for scanning."}

    if resp.status_code != 200:
        logger.warning("VirusTotal returned status %s", resp.status_code)
        return {"available": False, "reason": f"VirusTotal API error (status {resp.status_code})."}

    try:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, ValueError) as exc:
        logger.warning("Unexpected VirusTotal response shape: %s", exc)
        return {"available": False, "reason": "Unexpected response from VirusTotal."}

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    if malicious >= 3:
        recommendation = "Multiple security vendors flag this URL as malicious. Treat it as phishing/malware and do not visit it."
    elif malicious > 0 or suspicious > 0:
        recommendation = "A small number of vendors flag this URL as suspicious. Proceed with caution."
    else:
        recommendation = "No vendors currently flag this URL as malicious."

    return {
        "available": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_vendors": total,
        "recommendation": recommendation,
    }
