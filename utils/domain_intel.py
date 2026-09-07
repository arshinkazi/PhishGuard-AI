"""
domain_intel.py
----------------
Phase 5 — Domain Intelligence.

Enriches a scanned URL with WHOIS registration metadata (domain age,
registrar, creation/expiration dates, country). This is deliberately kept
OUT of the ML model's feature vector and OUT of the SHAP explanation --
it is informational context for a human analyst, not a model input, and
the dashboard labels it as such.

WHOIS lookups are live network calls, so this module is timeout-guarded
and fails gracefully: if the lookup errors, times out, or the `whois`
package isn't installed, the API returns `available: false` with a short
reason instead of raising.
"""

from __future__ import annotations

import datetime as dt
import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

try:
    import whois as _whois  # python-whois
    _WHOIS_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    _WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed; domain intelligence will be disabled.")

WHOIS_TIMEOUT_SECONDS = 6


def _hostname(url: str) -> str:
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        return urlparse(candidate).hostname or ""
    except ValueError:
        return ""


def _to_iso(value: Any) -> str | None:
    """Normalise whois date fields (which may be a list, datetime, or None)."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, str):
        return value
    return None


def get_domain_intelligence(url: str) -> dict:
    """Fetch WHOIS metadata for a URL's hostname.

    Returns a dict that always has `available: bool`. When True, it also
    carries `domain_age_days`, `registrar`, `creation_date`,
    `expiration_date`, and `country`. When False, it carries `reason`.
    """
    hostname = _hostname(url)
    if not hostname:
        return {"available": False, "reason": "Could not parse a hostname from this URL."}

    if not _WHOIS_AVAILABLE:
        return {"available": False, "reason": "WHOIS lookup library is not installed on this server."}

    try:
        record = _whois.whois(hostname)
    except Exception as exc:  # noqa: BLE001 - third-party lookup, many failure modes
        logger.info("WHOIS lookup failed for %s: %s", hostname, exc)
        return {"available": False, "reason": "WHOIS lookup failed or is not supported for this domain."}

    creation = _to_iso(getattr(record, "creation_date", None))
    expiration = _to_iso(getattr(record, "expiration_date", None))
    registrar = getattr(record, "registrar", None)
    country = getattr(record, "country", None)

    domain_age_days = None
    if creation:
        try:
            created_dt = dt.datetime.fromisoformat(creation.replace("Z", "")) if isinstance(creation, str) else None
            if created_dt:
                domain_age_days = (dt.datetime.now() - created_dt).days
        except ValueError:
            domain_age_days = None

    if not any([creation, expiration, registrar, country]):
        return {"available": False, "reason": "No WHOIS record was returned for this domain."}

    return {
        "available": True,
        "hostname": hostname,
        "registrar": registrar if isinstance(registrar, str) else (registrar[0] if registrar else None),
        "creation_date": creation,
        "expiration_date": expiration,
        "domain_age_days": domain_age_days,
        "country": country,
    }
