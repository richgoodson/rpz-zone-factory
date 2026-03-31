"""False-positive filtering logic.

Rules:
- Never block .gov, .mil, .edu TLDs
- Never block domains in the critical allowlist (~50 top domains)
- Deduplicate across all sources
- Log every skipped entry with reason
"""

from __future__ import annotations

import logging

from rpz_factory.models import EntryType, ThreatEntry

logger = logging.getLogger(__name__)

# TLDs that must never be blocked
SAFE_TLDS = frozenset({"gov", "mil", "edu"})

# Critical infrastructure / top domains that must never be blocked.
# Based on Alexa/Umbrella top sites — hardcoded subset of ~50.
CRITICAL_ALLOWLIST = frozenset({
    "google.com",
    "www.google.com",
    "googleapis.com",
    "gstatic.com",
    "google.co.uk",
    "google.ca",
    "google.de",
    "google.fr",
    "youtube.com",
    "www.youtube.com",
    "facebook.com",
    "www.facebook.com",
    "instagram.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "www.linkedin.com",
    "amazon.com",
    "www.amazon.com",
    "amazonaws.com",
    "cloudfront.net",
    "microsoft.com",
    "www.microsoft.com",
    "office.com",
    "office365.com",
    "live.com",
    "outlook.com",
    "windows.net",
    "azure.com",
    "apple.com",
    "www.apple.com",
    "icloud.com",
    "cloudflare.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "github.com",
    "www.github.com",
    "githubusercontent.com",
    "netflix.com",
    "www.netflix.com",
    "reddit.com",
    "www.reddit.com",
    "wikipedia.org",
    "www.wikipedia.org",
    "wikimedia.org",
    "whatsapp.com",
    "zoom.us",
    "dropbox.com",
    "akamai.net",
    "akamaiedge.net",
    "fastly.net",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "paypal.com",
    "www.paypal.com",
    "stripe.com",
    "shopify.com",
    "slack.com",
    "teams.microsoft.com",
})


def _get_tld(domain: str) -> str:
    """Return the effective TLD (last label) of a domain."""
    parts = domain.lower().rstrip(".").split(".")
    return parts[-1] if parts else ""


def _matches_allowlist(domain: str) -> str | None:
    """Check if domain or any parent domain is in the allowlist.

    Returns the matching allowlist entry, or None.
    """
    domain = domain.lower().rstrip(".")
    if domain in CRITICAL_ALLOWLIST:
        return domain

    # Check parent domains: sub.example.com → example.com
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in CRITICAL_ALLOWLIST:
            return parent

    return None


def filter_entries(entries: list[ThreatEntry]) -> list[ThreatEntry]:
    """Apply false-positive filters and deduplication.

    Returns the filtered list. Logs every skipped entry with reason.
    """
    seen: set[str] = set()
    accepted: list[ThreatEntry] = []
    stats = {"tld_safe": 0, "allowlist": 0, "duplicate": 0, "dns_invalid": 0, "accepted": 0}

    for entry in entries:
        norm = entry.normalized_value()

        # DNS validity check — reject domains with invalid label lengths,
        # slashes (URL paths), or total length > 253
        if entry.entry_type == EntryType.DOMAIN:
            if "/" in norm or len(norm) > 253:
                logger.debug(
                    "SKIP invalid DNS name: %s (source=%s)", norm, entry.source.value
                )
                stats["dns_invalid"] += 1
                continue
            if any(len(label) > 63 or len(label) == 0 for label in norm.split(".")):
                logger.debug(
                    "SKIP label too long: %s (source=%s)", norm, entry.source.value
                )
                stats["dns_invalid"] += 1
                continue

        # Dedup
        if norm in seen:
            logger.debug(
                "SKIP duplicate: %s (source=%s)", norm, entry.source.value
            )
            stats["duplicate"] += 1
            continue
        seen.add(norm)

        # TLD filter (only applies to domain entries)
        if entry.entry_type == EntryType.DOMAIN:
            tld = _get_tld(norm)
            if tld in SAFE_TLDS:
                logger.info(
                    "SKIP safe TLD (.%s): %s (source=%s)",
                    tld,
                    norm,
                    entry.source.value,
                )
                stats["tld_safe"] += 1
                continue

            # Allowlist check
            match = _matches_allowlist(norm)
            if match is not None:
                logger.info(
                    "SKIP allowlisted (%s): %s (source=%s)",
                    match,
                    norm,
                    entry.source.value,
                )
                stats["allowlist"] += 1
                continue

        accepted.append(entry)
        stats["accepted"] += 1

    logger.info(
        "Filter results: %d accepted, %d duplicates, %d safe-TLD, %d allowlisted, "
        "%d dns-invalid (from %d total)",
        stats["accepted"],
        stats["duplicate"],
        stats["tld_safe"],
        stats["allowlist"],
        stats["dns_invalid"],
        len(entries),
    )
    return accepted
