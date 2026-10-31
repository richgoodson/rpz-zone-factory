"""Parser for Abuse.ch URLhaus RPZ feed.

The feed is already in RPZ format; we parse the CNAME records out of it to
extract blocked domains. The URL comes from the registry (categories.py) and
requires a free abuse.ch Auth-Key, read from $ABUSECH_AUTH_KEY, since the
keyless endpoint was retired in October 2026.
"""

from __future__ import annotations

import logging
import os
import re

from rpz_factory.categories import REGISTRY
from rpz_factory.fetcher import (
    AUTH_KEY_PLACEHOLDER,
    NotModified,
    fetch_url,
    get_last_fetch_meta,
)
from rpz_factory.models import EntryType, FetchResult, HttpMeta, SourceName, ThreatEntry

logger = logging.getLogger(__name__)

AUTH_KEY_ENV = "ABUSECH_AUTH_KEY"

# Matches RPZ CNAME lines like:
#   malware.example.com CNAME .
#   *.malware.example.com CNAME .
_RPZ_CNAME_RE = re.compile(
    r"^(\*\.)?([a-zA-Z0-9._-]+)\s+(?:IN\s+)?CNAME\s+\.\s*(?:;.*)?$",
    re.IGNORECASE,
)


def fetch_and_parse(
    *,
    etag: str | None = None,
    last_modified: str | None = None,
) -> FetchResult:
    """Fetch URLhaus RPZ feed and extract domain entries."""
    result = FetchResult(source=SourceName.ABUSECH_URLHAUS)
    url = REGISTRY["urlhaus"].url
    auth_key = os.environ.get(AUTH_KEY_ENV, "").strip() or None
    if AUTH_KEY_PLACEHOLDER in url and not auth_key:
        result.error = (
            f"{AUTH_KEY_ENV} is not set; URLhaus downloads require a free "
            "Auth-Key from https://auth.abuse.ch/ (see README, abuse.ch Auth-Key)"
        )
        logger.error("URLhaus: %s", result.error)
        return result
    try:
        text = fetch_url(url, etag=etag, last_modified=last_modified, auth_key=auth_key)
        assert isinstance(text, str)
    except NotModified:
        result.not_modified = True
        return result
    except Exception as exc:
        logger.error("Failed to fetch URLhaus RPZ: %s", exc)
        result.error = str(exc)
        return result

    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";") or line.startswith("$"):
            continue
        # Skip SOA, NS, and other infrastructure records
        if line.startswith("@") or " SOA " in line.upper() or " NS " in line.upper():
            continue

        result.raw_count += 1
        m = _RPZ_CNAME_RE.match(line)
        if m:
            domain = m.group(2).lower().rstrip(".")
            if domain and domain not in seen:
                seen.add(domain)
                result.entries.append(
                    ThreatEntry(
                        value=domain,
                        entry_type=EntryType.DOMAIN,
                        source=SourceName.ABUSECH_URLHAUS,
                        raw_line=line,
                    )
                )

    logger.info(
        "URLhaus: parsed %d entries from %d raw lines",
        len(result.entries),
        result.raw_count,
    )
    return result
