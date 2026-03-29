"""Parser for CISA Known Exploited Vulnerabilities (KEV) feed.

The JSON feed contains CVE records. Some have associated domains or IPs
referenced in notes/descriptions. We also look at knownRansomwareCampaignUse
and other fields but primarily we extract any domains found in the data.

Since the KEV feed is vulnerability-focused (not an IOC feed), the domain
extraction is best-effort from URL-like patterns in text fields.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any
from urllib.parse import urlparse

from rpz_factory.fetcher import fetch_url
from rpz_factory.models import EntryType, FetchResult, SourceName, ThreatEntry

logger = logging.getLogger(__name__)

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# Match domains in text (simplified but effective)
_DOMAIN_RE = re.compile(
    r"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})",
)

# Known vendor/non-threat domains to skip from CISA descriptions
_VENDOR_DOMAINS = frozenset({
    "cisa.gov",
    "nist.gov",
    "nvd.nist.gov",
    "cve.org",
    "cve.mitre.org",
    "mitre.org",
    "github.com",
    "microsoft.com",
    "apache.org",
    "oracle.com",
    "adobe.com",
    "cisco.com",
    "vmware.com",
    "fortinet.com",
    "paloaltonetworks.com",
    "sap.com",
    "google.com",
    "apple.com",
    "mozilla.org",
    "debian.org",
    "ubuntu.com",
    "redhat.com",
    "kernel.org",
    "w3.org",
    "ietf.org",
})


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _extract_domains_from_text(text: str) -> list[str]:
    """Extract domain-like strings from free text."""
    domains: list[str] = []
    for m in _DOMAIN_RE.finditer(text):
        candidate = m.group(1).lower().rstrip(".")
        # Skip if it looks like a vendor domain
        if candidate in _VENDOR_DOMAINS:
            continue
        # Skip if any parent domain is a vendor domain
        parts = candidate.split(".")
        skip = False
        for i in range(len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in _VENDOR_DOMAINS:
                skip = True
                break
        if skip:
            continue
        # Must have at least one dot
        if "." in candidate and not _is_ip(candidate):
            domains.append(candidate)
    return domains


def fetch_and_parse() -> FetchResult:
    """Fetch CISA KEV JSON and extract domain/IP indicators."""
    result = FetchResult(source=SourceName.CISA_KEV)
    try:
        data: dict[str, Any] = fetch_url(CISA_KEV_URL, expect_json=True)  # type: ignore[assignment]
    except Exception as exc:
        logger.error("Failed to fetch CISA KEV: %s", exc)
        result.error = str(exc)
        return result

    vulnerabilities = data.get("vulnerabilities", [])
    result.raw_count = len(vulnerabilities)

    seen: set[str] = set()

    for vuln in vulnerabilities:
        # Scan text fields for domains
        text_fields = [
            vuln.get("shortDescription", ""),
            vuln.get("notes", ""),
            vuln.get("requiredAction", ""),
        ]
        for text in text_fields:
            if not text:
                continue
            for domain in _extract_domains_from_text(text):
                if domain not in seen:
                    seen.add(domain)
                    result.entries.append(
                        ThreatEntry(
                            value=domain,
                            entry_type=EntryType.DOMAIN,
                            source=SourceName.CISA_KEV,
                            raw_line=f"CVE: {vuln.get('cveID', 'unknown')}",
                        )
                    )

    logger.info(
        "CISA KEV: extracted %d domain entries from %d vulnerabilities",
        len(result.entries),
        result.raw_count,
    )
    return result
