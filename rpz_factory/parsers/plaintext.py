"""Generic parser for plaintext domain blocklists.

Handles the two common community-list formats:

    1. Hosts-file:    "0.0.0.0 example.com"    (or 127.0.0.1, ::, ::1)
    2. Plain domain:  "example.com"

Both formats often include "#"- and ";"-prefixed comments and blank lines.
Trailing inline comments after the domain are also stripped.

The factory function `make_fetcher(url, source_name)` returns a closure
with the same signature as the bespoke parser modules' `fetch_and_parse`,
so it drops into cli.py's `SOURCE_FETCHERS` dispatch table without any
special-casing.
"""

from __future__ import annotations

import logging
import re
from typing import Callable

from rpz_factory.fetcher import NotModified, fetch_url
from rpz_factory.models import EntryType, FetchResult, SourceName, ThreatEntry

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
# separately. We're permissive on Punycode (xn--) and IDN — labels match
# fine since they're already ACE-encoded.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
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
    # Reject "localhost", "localhost.localdomain", and similar — they
    # appear in hosts files but aren't real blocklist entries.
    if candidate in {"localhost", "localhost.localdomain", "broadcasthost"}:
        return None

    if not _DOMAIN_RE.match(candidate):
        return None
    return candidate


def parse_text(text: str, source: SourceName) -> FetchResult:
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


def make_fetcher(
    url: str,
    source: SourceName,
    *,
    label: str | None = None,
) -> Callable[..., FetchResult]:
    """Build a `fetch_and_parse(*, etag, last_modified)` closure for one feed.

    `label` is used in log lines; defaults to the SourceName value.
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

        result = parse_text(text, source)
        logger.info(
            "%s: parsed %d entries from %d lines",
            log_label,
            len(result.entries),
            result.raw_count,
        )
        return result

    return fetch_and_parse
