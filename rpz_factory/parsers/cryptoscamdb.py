"""Parser for CryptoScamDB domain blacklist.

The feed at https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/urls.yaml
is a YAML list of dicts with name, url, category, subcategory, and reporter fields.
We extract domains from the 'name' field, falling back to parsing the 'url' field.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import yaml

from rpz_factory.fetcher import fetch_url
from rpz_factory.models import EntryType, FetchResult, SourceName, ThreatEntry

logger = logging.getLogger(__name__)

CRYPTOSCAMDB_URL = (
    "https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/urls.yaml"
)


def _extract_domain(entry: dict) -> str | None:
    """Extract a clean domain from a CryptoScamDB entry.

    The 'name' field often contains full URLs with paths (e.g.,
    'docs.google.com/forms/d/...' or 'https://medium.com/@user/...').
    We always parse through urlparse to extract just the hostname.
    """
    for field in ("url", "name"):
        raw = entry.get(field, "")
        if not isinstance(raw, str) or not raw.strip():
            continue
        raw = raw.strip()

        # Ensure urlparse can parse it — add scheme if missing
        if not raw.startswith(("http://", "https://")):
            # If it contains a slash, it's likely a URL missing scheme
            if "/" in raw:
                raw = "http://" + raw
            else:
                # Plain domain — validate and return directly
                domain = raw.lower().rstrip(".")
                if "." in domain and " " not in domain and _is_valid_domain(domain):
                    return domain
                continue

        try:
            parsed = urlparse(raw)
            hostname = parsed.hostname
            if hostname:
                domain = hostname.lower().rstrip(".")
                if "." in domain and _is_valid_domain(domain):
                    return domain
        except Exception:
            continue

    return None


def _is_valid_domain(domain: str) -> bool:
    """Check that a domain has valid DNS label lengths."""
    if len(domain) > 253:
        return False
    for label in domain.split("."):
        if len(label) > 63 or len(label) == 0:
            return False
    return True


def fetch_and_parse() -> FetchResult:
    """Fetch CryptoScamDB YAML blacklist and extract domain entries."""
    result = FetchResult(source=SourceName.CRYPTOSCAMDB)
    try:
        text = fetch_url(CRYPTOSCAMDB_URL)
        assert isinstance(text, str)
    except Exception as exc:
        logger.error("Failed to fetch CryptoScamDB blacklist: %s", exc)
        result.error = str(exc)
        return result

    try:
        entries = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse CryptoScamDB YAML: %s", exc)
        result.error = str(exc)
        return result

    if not isinstance(entries, list):
        result.error = f"Expected YAML list, got {type(entries).__name__}"
        logger.error("CryptoScamDB: %s", result.error)
        return result

    result.raw_count = len(entries)
    seen: set[str] = set()

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        domain = _extract_domain(entry)
        if domain and domain not in seen:
            seen.add(domain)
            result.entries.append(
                ThreatEntry(
                    value=domain,
                    entry_type=EntryType.DOMAIN,
                    source=SourceName.CRYPTOSCAMDB,
                    raw_line=str(entry.get("name", entry.get("url", ""))),
                )
            )

    logger.info(
        "CryptoScamDB: parsed %d entries from %d raw records",
        len(result.entries),
        result.raw_count,
    )
    return result
