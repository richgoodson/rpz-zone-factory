"""Parser for Spamhaus DROP and DBL feeds.

DROP is a CIDR-based IP blocklist. Each line is:
    <cidr> ; <SBL-id>

DBL is a domain blocklist (one domain per line with comments).

(Spamhaus retired EDROP in 2024, folding its entries into DROP, so there is no
separate EDROP feed here.)
"""

from __future__ import annotations

import ipaddress
import logging
import re

from rpz_factory.fetcher import NotModified, fetch_url, get_last_fetch_meta
from rpz_factory.models import EntryType, FetchResult, HttpMeta, SourceName, ThreatEntry

logger = logging.getLogger(__name__)

DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
DBL_URL = "https://www.spamhaus.org/drop/dbl.txt"

# DROP line format: 1.2.3.0/24 ; SBLxxxxxx
_DROP_LINE_RE = re.compile(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s*;\s*(\S+)")

# DBL line: domain.tld  (may have trailing comment after ;)
# TLD is alphabetic or an ACE-encoded IDN TLD (xn--...), so Punycode TLDs match.
_DBL_LINE_RE = re.compile(
    r"^([a-zA-Z0-9._-]+\.(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9-]+))\s*(?:;.*)?$"
)


def _parse_drop_text(text: str, source: SourceName) -> FetchResult:
    """Parse DROP format text into CIDR entries."""
    result = FetchResult(source=source)
    seen: set[str] = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        result.raw_count += 1
        m = _DROP_LINE_RE.match(line)
        if m:
            cidr = m.group(1)
            # Validate the CIDR
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                logger.debug("Skipping invalid CIDR: %s", cidr)
                continue

            if cidr not in seen:
                seen.add(cidr)
                result.entries.append(
                    ThreatEntry(
                        value=cidr,
                        entry_type=EntryType.CIDR,
                        source=source,
                        raw_line=line,
                    )
                )

    return result


def fetch_drop(
    *,
    etag: str | None = None,
    last_modified: str | None = None,
) -> FetchResult:
    """Fetch and parse Spamhaus DROP list."""
    result = FetchResult(source=SourceName.SPAMHAUS_DROP)
    try:
        text = fetch_url(DROP_URL, etag=etag, last_modified=last_modified)
        assert isinstance(text, str)
    except NotModified:
        result.not_modified = True
        return result
    except Exception as exc:
        logger.error("Failed to fetch Spamhaus DROP: %s", exc)
        result.error = str(exc)
        return result

    result = _parse_drop_text(text, SourceName.SPAMHAUS_DROP)
    logger.info(
        "Spamhaus DROP: parsed %d CIDR entries from %d lines",
        len(result.entries),
        result.raw_count,
    )
    return result


def fetch_dbl() -> FetchResult:
    """Fetch and parse Spamhaus DBL (domain blocklist)."""
    result = FetchResult(source=SourceName.SPAMHAUS_DBL)
    try:
        text = fetch_url(DBL_URL)
        assert isinstance(text, str)
    except Exception as exc:
        # DBL may not be publicly accessible — this is expected
        logger.warning("Failed to fetch Spamhaus DBL (may require auth): %s", exc)
        result.error = str(exc)
        return result

    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        result.raw_count += 1
        m = _DBL_LINE_RE.match(line)
        if m:
            domain = m.group(1).lower().rstrip(".")
            if domain and domain not in seen:
                seen.add(domain)
                result.entries.append(
                    ThreatEntry(
                        value=domain,
                        entry_type=EntryType.DOMAIN,
                        source=SourceName.SPAMHAUS_DBL,
                        raw_line=line,
                    )
                )

    logger.info(
        "Spamhaus DBL: parsed %d domain entries from %d lines",
        len(result.entries),
        result.raw_count,
    )
    return result
