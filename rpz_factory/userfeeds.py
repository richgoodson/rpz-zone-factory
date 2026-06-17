"""Loader + validator for operator-defined web feeds (`user-feeds.yaml`).

This module is intentionally **dependency-free** with respect to the rest of
the package: it imports only the standard library and `yaml`, and it receives
the registry facts it validates against (the valid category set, the built-in
feed keys, the built-in zone names) as function arguments. `categories.py`
owns those facts and passes them in. Keeping the dependency arrow one-way
(`categories -> userfeeds`, never the reverse) means a malformed
`user-feeds.yaml` can never make the package unimportable - the worst case is
"built-ins only, plus a recorded issue".

Two modes:

* **lenient** (`strict=False`, the default used at registry-build time): a
  per-feed problem drops just that feed and records an issue; a file-level
  problem (unreadable / unparseable / wrong top-level shape) drops *all*
  custom feeds and records one issue. Never raises.
* **strict** (`strict=True`, used by the `validate-feeds` subcommand): collect
  every problem in one pass and raise `UserFeedError` carrying all of them, so
  the operator sees every mistake at once.
"""

from __future__ import annotations

import os
import re
import urllib.parse
from dataclasses import dataclass, field

import yaml

# A feed key must be a single DNS-safe label-ish token: lowercase letters,
# digits, and hyphens, starting with an alphanumeric. Underscores are
# disallowed so the hyphen->underscore mapping in `enum_value` stays injective
# (two distinct keys can never derive the same enum value).
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

_VALID_KINDS = ("domain", "ip")
_VALID_URL_SCHEMES = ("http", "https")

# Default config path: <repo-root>/user-feeds.yaml, where repo root is the
# parent of this package directory (matches how cli.py derives RPZ_DIR).
# RPZ_USER_FEEDS overrides it entirely.
_CONFIG_BASENAME = "user-feeds.yaml"


@dataclass(frozen=True)
class UserFeedSpec:
    """One validated operator-defined feed.

    `enum_value` and `zone` are derived, not stored, so they can never drift
    from `key`/`category`.
    """

    key: str
    category: str
    url: str
    kind: str = "domain"
    label: str | None = None

    @property
    def enum_value(self) -> str:
        """Source identity value, e.g. "user_my_bad_ips" for key "my-bad-ips".

        The `user_` prefix guarantees no collision with any built-in
        SourceName value.
        """
        return "user_" + self.key.replace("-", "_")

    @property
    def zone(self) -> str:
        """Derived zone filename, e.g. "my-bad-ips.ipreputation.rpz"."""
        return f"{self.key}.{self.category}.rpz"


@dataclass
class LoadResult:
    """Outcome of a lenient load: the feeds that validated, plus any issues."""

    specs: list[UserFeedSpec] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


class UserFeedError(Exception):
    """Raised by `load_user_feeds(strict=True)` when any problem is found.

    Carries the full list of issue strings so `validate-feeds` can print each.
    """

    def __init__(self, issues: list[str]):
        self.issues = list(issues)
        super().__init__("; ".join(self.issues))


def default_path() -> str:
    """Resolve the config path: $RPZ_USER_FEEDS, else <repo-root>/user-feeds.yaml."""
    override = os.environ.get("RPZ_USER_FEEDS")
    if override:
        return override
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(repo_root, _CONFIG_BASENAME)


def _coerce_feed(
    feed: object,
    index: int,
    *,
    valid_categories: set[str],
    builtin_keys: set[str],
    builtin_zones: set[str],
    seen_keys: set[str],
    seen_zones: set[str],
) -> tuple[UserFeedSpec | None, str | None]:
    """Validate one raw feed entry in a single pass.

    Returns `(spec, None)` if it validates, or `(None, issue)` describing the
    first problem found. Mutates `seen_keys`/`seen_zones` to detect intra-file
    duplicates. Checks are ordered structural-first, then cross-reference.
    """
    where = f"feed #{index + 1}"

    if not isinstance(feed, dict):
        return None, f"{where}: entry is not a mapping"

    # --- key: must exist, be DNS-safe, and be unique (file + built-ins) ---
    key = feed.get("key")
    if not isinstance(key, str) or not key:
        return None, f"{where}: 'key' is missing or not a string"
    if not _KEY_RE.match(key):
        return None, (
            f"{key}: key is not DNS-safe (allowed: lowercase letters, digits, "
            "hyphen; must start with a letter or digit)"
        )
    if key in seen_keys:
        return None, f"{key}: duplicate key in user-feeds file"
    seen_keys.add(key)
    if key in builtin_keys:
        return None, f"{key}: key collides with a built-in feed"

    # --- kind ---
    kind = feed.get("kind", "domain")
    if kind not in _VALID_KINDS:
        return None, f"{key}: kind {kind!r} is not 'domain' or 'ip'"

    # --- url: must exist and be http/https ---
    url = feed.get("url")
    if not isinstance(url, str) or not url:
        return None, f"{key}: 'url' is missing or not a string"
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme not in _VALID_URL_SCHEMES:
        return None, f"{key}: url scheme {scheme!r} is not http or https"

    # --- category: must exist and be a known category ---
    category = feed.get("category")
    if not isinstance(category, str) or not category:
        return None, f"{key}: 'category' is missing or not a string"
    if category not in valid_categories:
        return None, f"{key}: unknown category {category!r}"

    label = feed.get("label")
    if label is not None and not isinstance(label, str):
        label = None  # optional, log-only - ignore a malformed value silently

    spec = UserFeedSpec(key=key, category=category, url=url, kind=kind, label=label)

    # --- derived zone: must not collide with a built-in zone or an earlier
    # user feed's zone. This catches the case the key check misses, e.g.
    # key=spamhaus-drop + category=ipreputation derives
    # "spamhaus-drop.ipreputation.rpz", colliding with the built-in `drop`
    # feed's zone - two feeds rendering the same .db would corrupt live state.
    zone = spec.zone
    if zone in builtin_zones:
        return None, f"{key}: derived zone {zone!r} collides with a built-in zone"
    if zone in seen_zones:
        return None, f"{key}: derived zone {zone!r} collides with another user feed"
    seen_zones.add(zone)

    return spec, None


def load_user_feeds(
    *,
    valid_categories,
    builtin_keys,
    builtin_zones,
    strict: bool = False,
    path: str | None = None,
) -> LoadResult:
    """Load and validate `user-feeds.yaml`.

    `valid_categories`, `builtin_keys`, and `builtin_zones` are the registry
    facts to validate against. `builtin_keys`/`builtin_zones` are expected to
    already include the allowlist (key "allowlist", zone "allowlist.rpz").

    Lenient (`strict=False`): never raises. A missing file yields an empty
    result. A file-level error yields no specs plus one issue. A per-feed error
    drops that feed plus records one issue.

    Strict (`strict=True`): a file-level error raises immediately; per-feed
    errors are collected across the whole file and raised together. Raises
    `UserFeedError`.
    """
    valid_categories = set(valid_categories)
    builtin_keys = set(builtin_keys)
    builtin_zones = set(builtin_zones)

    feeds_path = path if path is not None else default_path()

    # Missing file is the common, zero-config case: no custom feeds, no issue.
    if not os.path.exists(feeds_path):
        return LoadResult()

    # --- file-level: read + parse ---
    try:
        with open(feeds_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as exc:
        msg = f"{feeds_path}: cannot read/parse ({exc})"
        if strict:
            raise UserFeedError([msg]) from exc
        return LoadResult(issues=[msg])

    # Empty file (or a file that is only comments) parses to None.
    if raw is None:
        return LoadResult()

    if not isinstance(raw, dict) or "feeds" not in raw:
        msg = f"{feeds_path}: top-level 'feeds:' key is missing"
        if strict:
            raise UserFeedError([msg])
        return LoadResult(issues=[msg])

    feeds_raw = raw.get("feeds")
    if feeds_raw is None:
        return LoadResult()  # `feeds:` present but empty - no custom feeds.
    if not isinstance(feeds_raw, list):
        msg = f"{feeds_path}: 'feeds' must be a list"
        if strict:
            raise UserFeedError([msg])
        return LoadResult(issues=[msg])

    # --- per-feed: one validation pass ---
    result = LoadResult()
    seen_keys: set[str] = set()
    seen_zones: set[str] = set()

    for index, feed in enumerate(feeds_raw):
        spec, issue = _coerce_feed(
            feed,
            index,
            valid_categories=valid_categories,
            builtin_keys=builtin_keys,
            builtin_zones=builtin_zones,
            seen_keys=seen_keys,
            seen_zones=seen_zones,
        )
        if issue is not None:
            result.issues.append(issue)
        elif spec is not None:
            result.specs.append(spec)

    if strict and result.issues:
        raise UserFeedError(result.issues)

    return result
