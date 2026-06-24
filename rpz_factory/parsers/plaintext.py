"""Generic parser for plaintext domain and IPv4 blocklists.

Domain feeds handle the two common community-list formats:

    1. Hosts-file:    "0.0.0.0 example.com"    (or 127.0.0.1, ::, ::1)
    2. Plain domain:  "example.com"

IP feeds (`kind="ip"`) handle plain IPv4 address and CIDR lists:

    3. Bare address:  "1.2.3.4"        -> EntryType.IP
    4. CIDR network:  "1.2.3.0/24"     -> EntryType.CIDR

All formats often include "#"- and ";"-prefixed comments and blank lines.
Trailing inline comments are stripped.

The factory function `make_fetcher(url, source, *, label, kind)` returns a
closure with the same signature as the bespoke parser modules'
`fetch_and_parse`, so it drops into cli.py's `SOURCE_FETCHERS` dispatch table
without any special-casing. `kind` selects the domain vs IPv4 parser.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Callable

from rpz_factory.fetcher import NotModified, fetch_url
from rpz_factory.models import EntryType, FetchResult, SourceName, SourceRef, ThreatEntry

logger = logging.getLogger(__name__)

# Bind addresses commonly used as the "blackhole" target in hosts files.
# When a line starts with one of these followed by whitespace, we treat
# the rest of the line as the blocked-domain field.
_HOSTS_PREFIXES = (
    "0.0.0.0",
    "127.0.0.1",
    "::1",
    "::",
)

# Domain validation: at least one dot, label rules per RFC 1035 (length
# 1-63, alnum + hyphen, no leading/trailing hyphen). Total length checked
# separately. The TLD label is alphabetic OR an ACE-encoded IDN TLD (xn--...,
# e.g. .рф -> xn--p1ai), so Punycode TLDs are not silently dropped.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9-]{1,59})$"
)


def _extract_domain(line: str) -> str | None:
    """Return a normalized domain from one input line, or None if there isn't one."""
    # Strip trailing comments (# or ; after the domain).
    for marker in ("#", ";"):
        idx = line.find(marker)
        if idx >= 0:
            line = line[:idx]
    line = line.strip()
    if not line:
        return None

    parts = line.split()
    if not parts:
        return None

    # Hosts-file form: blackhole IP first, domain second.
    if parts[0] in _HOSTS_PREFIXES:
        if len(parts) < 2:
            return None
        candidate = parts[1]
    else:
        # Plain-domain form: first whitespace-separated token is the domain.
        candidate = parts[0]

    # Some upstream feeds (notably firebog's Prigent-Crypto) emit malformed
    # lines like "0.0.0.0example.com" with no whitespace separator. Strip
    # any leading hosts-file IP that's glued directly to the domain.
    for _pfx in _HOSTS_PREFIXES:
        if candidate.startswith(_pfx) and len(candidate) > len(_pfx):
            tail = candidate[len(_pfx):]
            if tail and tail[0].isalpha():
                candidate = tail
                break

    candidate = candidate.lower().rstrip(".")
    # Reject "localhost", "localhost.localdomain", and similar - they
    # appear in hosts files but aren't real blocklist entries.
    if candidate in {"localhost", "localhost.localdomain", "broadcasthost"}:
        return None

    if not _DOMAIN_RE.match(candidate):
        return None
    return candidate


def parse_text(text: str, source: SourceName | SourceRef) -> FetchResult:
    """Parse plaintext blocklist content into a FetchResult.

    Exposed separately so unit tests can exercise the parser without HTTP.
    """
    result = FetchResult(source=source)
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Whole-line comment markers.
        if line.startswith("#") or line.startswith(";") or line.startswith("!"):
            continue
        result.raw_count += 1
        domain = _extract_domain(line)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        result.entries.append(
            ThreatEntry(
                value=domain,
                entry_type=EntryType.DOMAIN,
                source=source,
                raw_line=raw,
            )
        )
    return result


def parse_ip_text(
    text: str,
    source: SourceName | SourceRef,
    *,
    label: str | None = None,
) -> FetchResult:
    """Parse a plaintext IPv4 address/CIDR blocklist into a FetchResult.

    Takes the first whitespace token per line (after stripping `#`/`;`
    comments). A token with a `/` is parsed as a network (`strict=False`, so
    host bits are masked off and the value is normalized to `network/prefix`);
    otherwise as a bare address. Only IPv4 is accepted - the RPZ renderer's
    `rpz-ip` encoding is IPv4-only - so IPv6 lines are dropped here, where the
    per-feed count reflects what actually renders. There is no `/24` floor: the
    renderer accepts `/1`-`/32` and drops only `/0`, so parser counts match the
    rendered zone.

    Drop counts are surfaced at WARNING when total drops (IPv6 + unparseable)
    exceed kept entries - i.e. the feed lost more than half its lines, the
    signal that it collapsed to a near-empty zone. Otherwise they log at INFO.
    """
    log_label = label or source.value
    result = FetchResult(source=source)
    seen: set[str] = set()
    dropped_ipv6 = 0
    dropped_unparseable = 0

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # Whole-line comment markers.
        if line.startswith("#") or line.startswith(";") or line.startswith("!"):
            continue
        # Strip trailing inline comments (# or ; after the token).
        for marker in ("#", ";"):
            idx = line.find(marker)
            if idx >= 0:
                line = line[:idx]
        line = line.strip()
        if not line:
            continue

        token = line.split()[0]
        result.raw_count += 1
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                if net.version != 4:
                    dropped_ipv6 += 1
                    continue
                value = str(net)
                entry_type = EntryType.CIDR
            else:
                addr = ipaddress.ip_address(token)
                if addr.version != 4:
                    dropped_ipv6 += 1
                    continue
                value = str(addr)
                entry_type = EntryType.IP
        except ValueError:
            dropped_unparseable += 1
            continue

        if value in seen:
            continue
        seen.add(value)
        result.entries.append(
            ThreatEntry(
                value=value,
                entry_type=entry_type,
                source=source,
                raw_line=raw,
            )
        )

    kept = len(result.entries)
    drops = dropped_ipv6 + dropped_unparseable
    level = logging.WARNING if drops > kept else logging.INFO
    logger.log(
        level,
        "%s: kept %d, dropped %d IPv6, dropped %d unparseable",
        log_label,
        kept,
        dropped_ipv6,
        dropped_unparseable,
    )
    return result


def make_fetcher(
    url: str,
    source: SourceName | SourceRef,
    *,
    label: str | None = None,
    kind: str = "domain",
) -> Callable[..., FetchResult]:
    """Build a `fetch_and_parse(*, etag, last_modified)` closure for one feed.

    `label` is used in log lines; defaults to the source's `.value`. `kind`
    selects the parser: "domain" (default) routes to `parse_text`, "ip" routes
    to `parse_ip_text`.
    """
    log_label = label or source.value

    def fetch_and_parse(
        *,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> FetchResult:
        result = FetchResult(source=source)
        try:
            text = fetch_url(url, etag=etag, last_modified=last_modified)
            assert isinstance(text, str)
        except NotModified:
            result.not_modified = True
            return result
        except Exception as exc:
            logger.error("Failed to fetch %s (%s): %s", log_label, url, exc)
            result.error = str(exc)
            return result

        if kind == "ip":
            # parse_ip_text logs its own kept/dropped breakdown (with WARNING
            # escalation), so we don't add the generic domain-style line here.
            return parse_ip_text(text, source, label=log_label)

        result = parse_text(text, source)
        logger.info(
            "%s: parsed %d entries from %d lines",
            log_label,
            len(result.entries),
            result.raw_count,
        )
        return result

    return fetch_and_parse
