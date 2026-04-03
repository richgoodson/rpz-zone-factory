"""Parser for Scam Sniffer scam domain blacklist.

The feed at https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json
is a plain JSON array of domain strings.
"""

from __future__ import annotations

import json
import logging

from rpz_factory.fetcher import NotModified, fetch_url, get_last_fetch_meta
from rpz_factory.models import EntryType, FetchResult, HttpMeta, SourceName, ThreatEntry

logger = logging.getLogger(__name__)

SCAMSNIFFER_URL = (
    "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json"
)


def fetch_and_parse(
    *,
    etag: str | None = None,
    last_modified: str | None = None,
) -> FetchResult:
    """Fetch Scam Sniffer domain blacklist and extract domain entries."""
    result = FetchResult(source=SourceName.SCAMSNIFFER)
    try:
        text = fetch_url(SCAMSNIFFER_URL, etag=etag, last_modified=last_modified)
        assert isinstance(text, str)
    except NotModified:
        result.not_modified = True
        return result
    except Exception as exc:
        logger.error("Failed to fetch Scam Sniffer blacklist: %s", exc)
        result.error = str(exc)
        return result

    try:
        domains = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Scam Sniffer JSON: %s", exc)
        result.error = str(exc)
        return result

    if not isinstance(domains, list):
        result.error = f"Expected JSON array, got {type(domains).__name__}"
        logger.error("Scam Sniffer: %s", result.error)
        return result

    result.raw_count = len(domains)
    seen: set[str] = set()

    for raw_domain in domains:
        if not isinstance(raw_domain, str):
            continue
        domain = raw_domain.strip().lower().rstrip(".")
        if not domain or "." not in domain:
            continue
        if domain not in seen:
            seen.add(domain)
            result.entries.append(
                ThreatEntry(
                    value=domain,
                    entry_type=EntryType.DOMAIN,
                    source=SourceName.SCAMSNIFFER,
                    raw_line=raw_domain,
                )
            )

    logger.info(
        "Scam Sniffer: parsed %d entries from %d raw domains",
        len(result.entries),
        result.raw_count,
    )
    return result
