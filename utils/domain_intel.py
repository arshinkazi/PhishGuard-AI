"""
domain_intel.py
----------------

Domain registration information used as supplementary context for a scan.

RDAP is used first because it is the modern HTTP-based registration data
service. A small WHOIS fallback is retained for domains that do not return a
usable RDAP response. Domain intelligence is never added to the ML feature
vector or SHAP explanation.
"""

from __future__ import annotations

import datetime as dt
import logging
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

try:
    import whois as _whois  # python-whois, fallback only
    _WHOIS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _WHOIS_AVAILABLE = False

RDAP_TIMEOUT_SECONDS = 6
WHOIS_TIMEOUT_SECONDS = 6
IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK_URL = "https://rdap.org/domain/{hostname}"


def _hostname(url: str) -> str:
    candidate = url.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        return (urlparse(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _to_iso(value: Any) -> str | None:
    if isinstance(value, list):
        value = next((item for item in value if item), None)
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, str):
        return value
    return None


def _parse_rdap_date(events: list[dict[str, Any]], event_action: str) -> str | None:
    for event in events or []:
        if event.get("eventAction") == event_action:
            return _to_iso(event.get("eventDate"))
    return None


def _rdap_entity_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            value = item[3]
            if isinstance(value, str):
                return value
    return None


def _rdap_country(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for item in vcard[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "adr":
            value = item[3]
            if isinstance(value, dict):
                country = value.get("country")
                if country:
                    return str(country)
            elif isinstance(value, list) and value:
                return str(value[-1]) if value[-1] else None
    return None


def _parse_rdap_record(record: dict[str, Any], hostname: str) -> dict[str, Any] | None:
    creation = _parse_rdap_date(record.get("events", []), "registration")
    expiration = _parse_rdap_date(record.get("events", []), "expiration")

    registrar = None
    country = None
    for entity in record.get("entities", []) or []:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles", []) or []
        if "registrar" in roles and not registrar:
            registrar = _rdap_entity_name(entity)
        if not country:
            country = _rdap_country(entity)

    if not any([creation, expiration, registrar, country]):
        return None

    domain_age_days = None
    if creation:
        try:
            created = dt.datetime.fromisoformat(creation.replace("Z", "+00:00"))
            now = dt.datetime.now(dt.timezone.utc)
            if created.tzinfo is None:
                created = created.replace(tzinfo=dt.timezone.utc)
            domain_age_days = max(0, (now - created).days)
        except ValueError:
            pass

    return {
        "available": True,
        "hostname": hostname,
        "registrar": registrar,
        "creation_date": creation,
        "expiration_date": expiration,
        "domain_age_days": domain_age_days,
        "country": country,
        "source": "RDAP",
    }


def _rdap_urls(hostname: str) -> list[str]:
    urls = []
    labels = hostname.split(".")
    if len(labels) < 2:
        return urls
    tld = labels[-1].lower()

    try:
        response = requests.get(IANA_BOOTSTRAP_URL, timeout=RDAP_TIMEOUT_SECONDS)
        response.raise_for_status()
        services = response.json().get("services", [])
        for entry in services:
            if not isinstance(entry, list) or len(entry) != 2:
                continue
            domains, base_urls = entry
            if tld in domains:
                for base in base_urls:
                    urls.append(base.rstrip("/") + "/domain/" + hostname)
    except (requests.RequestException, ValueError, TypeError) as exc:
        logger.info("RDAP bootstrap lookup failed: %s", exc)

    urls.append(RDAP_FALLBACK_URL.format(hostname=hostname))
    return list(dict.fromkeys(urls))


def _lookup_rdap(hostname: str) -> dict[str, Any] | None:
    for url in _rdap_urls(hostname):
        try:
            response = requests.get(
                url,
                headers={"Accept": "application/rdap+json, application/json"},
                timeout=RDAP_TIMEOUT_SECONDS,
                allow_redirects=True,
            )
            if response.status_code != 200:
                continue
            record = response.json()
            if isinstance(record, dict):
                parsed = _parse_rdap_record(record, hostname)
                if parsed:
                    return parsed
        except (requests.RequestException, ValueError, TypeError) as exc:
            logger.info("RDAP lookup failed for %s: %s", hostname, exc)
    return None


def _lookup_whois(hostname: str) -> dict[str, Any] | None:
    if not _WHOIS_AVAILABLE:
        return None
    try:
        record = _whois.whois(hostname)
    except Exception as exc:  # noqa: BLE001
        logger.info("WHOIS fallback failed for %s: %s", hostname, exc)
        return None

    creation = _to_iso(getattr(record, "creation_date", None))
    expiration = _to_iso(getattr(record, "expiration_date", None))
    registrar = getattr(record, "registrar", None)
    country = getattr(record, "country", None)
    registrar = registrar if isinstance(registrar, str) else (registrar[0] if registrar else None)
    country = country if isinstance(country, str) else (country[0] if country else None)

    if not any([creation, expiration, registrar, country]):
        return None

    domain_age_days = None
    if creation:
        try:
            created = dt.datetime.fromisoformat(creation.replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=dt.timezone.utc)
            domain_age_days = max(0, (dt.datetime.now(dt.timezone.utc) - created).days)
        except ValueError:
            pass

    return {
        "available": True,
        "hostname": hostname,
        "registrar": registrar,
        "creation_date": creation,
        "expiration_date": expiration,
        "domain_age_days": domain_age_days,
        "country": country,
        "source": "WHOIS",
    }


def get_domain_intelligence(url: str) -> dict[str, Any]:
    """Return registration metadata without affecting the ML verdict."""
    hostname = _hostname(url)
    if not hostname:
        return {"available": False, "reason": "Could not parse a hostname from this URL."}

    rdap_result = _lookup_rdap(hostname)
    if rdap_result:
        return rdap_result

    whois_result = _lookup_whois(hostname)
    if whois_result:
        return whois_result

    return {
        "available": False,
        "hostname": hostname,
        "reason": "Registration data is not available for this domain.",
    }
