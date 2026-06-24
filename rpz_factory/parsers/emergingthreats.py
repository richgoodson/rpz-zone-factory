"""Parser for the Emerging Threats compromised-IPs feed.

Source: https://rules.emergingthreats.net/blockrules/compromised-ips.txt

Format: flat text, one IPv4 address per line. No comments, no CIDRs.
We deliberately use this feed instead of `emerging-Block-IPs.txt` — the
latter mixes individual hosts with very large consumer-broadband network
blocks (down to /12) that are not safe to render into RPZ.
"""

from __future__ import annotations

import ipaddress
import logging

from rpz_factory.fetcher import NotModified, fetch_url
from rpz_factory.models import EntryType, FetchResult, SourceName, ThreatEntry

logger = logging.getLogger(__name__)

ET_COMPROMISED_IPS_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"


def fetch_and_parse(
    *,
    etag: str | None = None,
    last_modified: str | None = None,
) -> FetchResult:
    """Fetch and parse the Emerging Threats compromised-IPs list."""
    result = FetchResult(source=SourceName.ET_COMPROMISED_IPS)
    try:
        text = fetch_url(ET_COMPROMISED_IPS_URL, etag=etag, last_modified=last_modified)
        assert isinstance(text, str)
    except NotModified:
        result.not_modified = True
        return result
    except Exception as exc:
        logger.error("Failed to fetch ET compromised-ips: %s", exc)
        result.error = str(exc)
        return result

    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        result.raw_count += 1
        token = line.split()[0]

        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            logger.debug("Skipping non-IP line: %s", token)
            continue

        # rpz-ip encoding is IPv4-only; an IPv6 address would render as a
        # garbage owner name BIND rejects at zone load. Drop it here.
        if ip.version != 4:
            logger.debug("Skipping non-IPv4 address: %s", token)
            continue

        value = str(ip)
        if value in seen:
            continue
        seen.add(value)
        result.entries.append(
            ThreatEntry(
                value=value,
                entry_type=EntryType.IP,
                source=SourceName.ET_COMPROMISED_IPS,
                raw_line=line,
            )
        )

    logger.info(
        "ET compromised-ips: parsed %d entries from %d lines",
        len(result.entries),
        result.raw_count,
    )
    return result
