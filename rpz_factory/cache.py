"""Per-source cache for stale-data preservation.

When a source fetch succeeds, entries are cached to disk. When a fetch fails,
the cache is consulted so the source's last-known-good data is preserved.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from rpz_factory.models import EntryType, FetchResult, HttpMeta, SourceName, ThreatEntry

logger = logging.getLogger(__name__)


def _cache_path(cache_dir: str, source_name: str) -> Path:
    return Path(cache_dir) / f"{source_name}.json"


def _meta_path(cache_dir: str, source_name: str) -> Path:
    return Path(cache_dir) / f"{source_name}.meta.json"


def write_http_meta(cache_dir: str, source: SourceName, meta: HttpMeta) -> None:
    """Persist HTTP conditional-request metadata for a source."""
    if not meta.etag and not meta.last_modified:
        return
    path = _meta_path(cache_dir, source.value)
    os.makedirs(cache_dir, exist_ok=True)
    data = {
        "source": source.value,
        "etag": meta.etag,
        "last_modified": meta.last_modified,
        "saved_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.debug("HTTP meta written: %s", path)
    except OSError as exc:
        logger.warning("Failed to write HTTP meta for %s: %s", source.value, exc)


def load_http_meta(cache_dir: str, source: SourceName) -> HttpMeta | None:
    """Load persisted HTTP conditional-request metadata for a source."""
    path = _meta_path(cache_dir, source.value)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return HttpMeta(etag=data.get("etag"), last_modified=data.get("last_modified"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read HTTP meta for %s: %s", source.value, exc)
        return None


def write_cache(cache_dir: str, result: FetchResult) -> None:
    """Write a successful FetchResult's entries to the cache."""
    if not result.entries:
        return

    path = _cache_path(cache_dir, result.source.value)
    os.makedirs(cache_dir, exist_ok=True)

    data = {
        "source": result.source.value,
        "cached_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entry_count": len(result.entries),
        "entries": [
            {
                "value": e.value,
                "entry_type": e.entry_type.value,
                "raw_line": e.raw_line,
            }
            for e in result.entries
        ],
    }

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.debug("Cache written: %s (%d entries)", path, len(result.entries))
    except OSError as exc:
        logger.warning("Failed to write cache for %s: %s", result.source.value, exc)


def load_cache(cache_dir: str, source: SourceName) -> FetchResult | None:
    """Load cached entries for a source. Returns None if no cache exists."""
    path = _cache_path(cache_dir, source.value)

    if not path.exists():
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read cache for %s: %s", source.value, exc)
        return None

    entries_raw = data.get("entries", [])
    if not entries_raw:
        return None

    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    cached_at = data.get("cached_at", mtime.strftime("%Y-%m-%dT%H:%M:%SZ"))

    result = FetchResult(source=source)
    for e in entries_raw:
        try:
            result.entries.append(
                ThreatEntry(
                    value=e["value"],
                    entry_type=EntryType(e["entry_type"]),
                    source=source,
                    raw_line=e.get("raw_line", ""),
                )
            )
        except (KeyError, ValueError) as exc:
            logger.debug("Skipping invalid cache entry: %s", exc)
            continue

    result.raw_count = len(result.entries)
    logger.info(
        "Source %s: using cached data from %s (%d entries)",
        source.value,
        cached_at,
        len(result.entries),
    )
    return result
