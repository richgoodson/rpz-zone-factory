"""Tests for rpz_factory.userfeeds (load + one-pass validation, lenient + strict)."""

from __future__ import annotations

import textwrap

import pytest
import yaml

from rpz_factory.userfeeds import (
    LoadResult,
    UserFeedError,
    UserFeedSpec,
    load_user_feeds,
)

# Self-contained registry facts so these tests do not depend on categories.py.
# These mirror the real shape: a category set, built-in keys (incl. allowlist),
# and built-in zones (incl. allowlist.rpz, and one real-ish zone to test the
# derived-zone-collision case).
VALID_CATEGORIES = {
    "malware",
    "ads",
    "tracking",
    "scam",
    "cryptojacking",
    "ipreputation",
    "vulnerabilities",
}
BUILTIN_KEYS = {"urlhaus", "drop", "adguard-dns", "allowlist"}
BUILTIN_ZONES = {
    "urlhaus.malware.rpz",
    "spamhaus-drop.ipreputation.rpz",  # the built-in `drop` feed's zone
    "adguard-dns.ads.rpz",
    "allowlist.rpz",
}


def _load(path, strict=False):
    return load_user_feeds(
        valid_categories=VALID_CATEGORIES,
        builtin_keys=BUILTIN_KEYS,
        builtin_zones=BUILTIN_ZONES,
        strict=strict,
        path=str(path),
    )


def _write(tmp_path, body):
    p = tmp_path / "user-feeds.yaml"
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_valid_domain_and_ip_feeds(tmp_path):
    p = _write(
        tmp_path,
        """
        feeds:
          - key: my-corp-blocklist
            category: malware
            url: https://example.com/blocklist.txt
            kind: domain
            label: "Corp blocklist"
          - key: my-bad-ips
            category: ipreputation
            url: https://example.com/bad-ips.txt
            kind: ip
        """,
    )
    result = _load(p)

    assert result.issues == []
    assert [s.key for s in result.specs] == ["my-corp-blocklist", "my-bad-ips"]

    domain, ip = result.specs
    assert domain.kind == "domain"
    assert domain.label == "Corp blocklist"
    assert domain.zone == "my-corp-blocklist.malware.rpz"
    assert ip.kind == "ip"
    assert ip.zone == "my-bad-ips.ipreputation.rpz"


def test_kind_defaults_to_domain(tmp_path):
    p = _write(
        tmp_path,
        """
        feeds:
          - key: nodef
            category: ads
            url: https://example.com/list.txt
        """,
    )
    result = _load(p)
    assert result.issues == []
    assert result.specs[0].kind == "domain"
    assert result.specs[0].label is None


def test_enum_value_maps_hyphen_to_underscore_with_prefix():
    spec = UserFeedSpec(key="my-bad-ips", category="ipreputation", url="https://x/y")
    assert spec.enum_value == "user_my_bad_ips"
    # single-token key keeps the prefix, no underscores
    assert UserFeedSpec(key="foo", category="ads", url="https://x").enum_value == "user_foo"


def test_missing_file_yields_empty_result(tmp_path):
    result = _load(tmp_path / "does-not-exist.yaml")
    assert isinstance(result, LoadResult)
    assert result.specs == []
    assert result.issues == []


def test_empty_and_feedless_files_yield_empty_result(tmp_path):
    empty = _write(tmp_path, "\n# just a comment\n")
    assert _load(empty).specs == []
    assert _load(empty).issues == []

    feedless = tmp_path / "feedless.yaml"
    feedless.write_text("feeds:\n", encoding="utf-8")  # feeds: present but null
    res = _load(feedless)
    assert res.specs == []
    assert res.issues == []


# --------------------------------------------------------------------------- #
# Per-feed graceful degradation (lenient): each bad feed drops, rest survive
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "bad_feed, needle",
    [
        # bad key regex (underscore not allowed)
        ({"key": "bad_key", "category": "ads", "url": "https://x/y"}, "DNS-safe"),
        # bad kind
        ({"key": "badkind", "category": "ads", "url": "https://x/y", "kind": "cidr"}, "kind"),
        # bad URL scheme
        ({"key": "badurl", "category": "ads", "url": "ftp://x/y"}, "scheme"),
        # missing URL
        ({"key": "nourl", "category": "ads"}, "'url' is missing"),
        # unknown category
        ({"key": "badcat", "category": "malwre", "url": "https://x/y"}, "unknown category"),
        # key collides with a built-in feed
        ({"key": "urlhaus", "category": "ads", "url": "https://x/y"}, "collides with a built-in feed"),
        # key collides with the allowlist key
        ({"key": "allowlist", "category": "ads", "url": "https://x/y"}, "collides with a built-in feed"),
    ],
)
def test_per_feed_error_drops_only_offender(tmp_path, bad_feed, needle):
    # A valid feed before and after the bad one - both must survive. Build the
    # document structurally so feed shape never depends on string indentation.
    doc = {
        "feeds": [
            {"key": "keeper-one", "category": "ads", "url": "https://example.com/a.txt"},
            bad_feed,
            {"key": "keeper-two", "category": "malware", "url": "https://example.com/b.txt"},
        ]
    }
    p = tmp_path / "user-feeds.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")

    result = _load(p)

    keys = [s.key for s in result.specs]
    assert keys == ["keeper-one", "keeper-two"]
    assert len(result.issues) == 1
    assert needle in result.issues[0]


def test_duplicate_key_within_file(tmp_path):
    p = _write(
        tmp_path,
        """
        feeds:
          - key: dup
            category: ads
            url: https://example.com/a.txt
          - key: dup
            category: malware
            url: https://example.com/b.txt
        """,
    )
    result = _load(p)
    assert [s.key for s in result.specs] == ["dup"]  # first wins
    assert len(result.issues) == 1
    assert "duplicate key" in result.issues[0]


def test_derived_zone_collision_with_builtin_zone_whose_key_differs(tmp_path):
    # key=spamhaus-drop + category=ipreputation derives
    # "spamhaus-drop.ipreputation.rpz", which is the built-in `drop` feed's
    # zone - even though the key "spamhaus-drop" is not itself a built-in key.
    p = _write(
        tmp_path,
        """
        feeds:
          - key: spamhaus-drop
            category: ipreputation
            url: https://example.com/drop.txt
        """,
    )
    result = _load(p)
    assert result.specs == []
    assert len(result.issues) == 1
    assert "collides with a built-in zone" in result.issues[0]


def test_user_vs_user_same_zone_is_caught_as_duplicate_key(tmp_path):
    # The only way two user feeds derive the same zone is identical key AND
    # category (zone = "<key>.<category>.rpz" embeds the full key). Distinct
    # keys can never collide on zone, and an identical key is caught by the
    # duplicate-key guard *before* the zone check. So the within-file
    # zone-collision branch is unreachable from user-vs-user; the built-in
    # zone-collision test above is what exercises the zone guard for real.
    p = _write(
        tmp_path,
        """
        feeds:
          - key: collide
            category: ads
            url: https://example.com/a.txt
          - key: collide
            category: ads
            url: https://example.com/b.txt
        """,
    )
    result = _load(p)
    assert [s.key for s in result.specs] == ["collide"]
    assert any("duplicate key" in i for i in result.issues)


def test_non_mapping_feed_entry(tmp_path):
    p = _write(
        tmp_path,
        """
        feeds:
          - "just a string"
          - key: good
            category: ads
            url: https://example.com/a.txt
        """,
    )
    result = _load(p)
    assert [s.key for s in result.specs] == ["good"]
    assert len(result.issues) == 1
    assert "not a mapping" in result.issues[0]


# --------------------------------------------------------------------------- #
# File-level graceful degradation (lenient): drop all custom feeds
# --------------------------------------------------------------------------- #


def test_unparseable_yaml_drops_all(tmp_path):
    p = tmp_path / "user-feeds.yaml"
    p.write_text("feeds: [unterminated\n", encoding="utf-8")
    result = _load(p)
    assert result.specs == []
    assert len(result.issues) == 1
    assert "cannot read/parse" in result.issues[0]


def test_wrong_top_level_shape_drops_all(tmp_path):
    p = _write(tmp_path, "- key: foo\n  category: ads\n  url: https://x/y\n")  # a list, not a dict
    result = _load(p)
    assert result.specs == []
    assert len(result.issues) == 1
    assert "top-level 'feeds:'" in result.issues[0]


def test_feeds_not_a_list_drops_all(tmp_path):
    p = _write(tmp_path, "feeds: not-a-list\n")
    result = _load(p)
    assert result.specs == []
    assert len(result.issues) == 1
    assert "'feeds' must be a list" in result.issues[0]


# --------------------------------------------------------------------------- #
# Strict mode
# --------------------------------------------------------------------------- #


def test_strict_clean_file_does_not_raise(tmp_path):
    p = _write(
        tmp_path,
        """
        feeds:
          - key: ok
            category: ads
            url: https://example.com/a.txt
        """,
    )
    result = _load(p, strict=True)
    assert [s.key for s in result.specs] == ["ok"]
    assert result.issues == []


def test_strict_reports_all_problems_at_once(tmp_path):
    p = _write(
        tmp_path,
        """
        feeds:
          - key: bad_key
            category: ads
            url: https://example.com/a.txt
          - key: badcat
            category: nope
            url: https://example.com/b.txt
          - key: badurl
            category: ads
            url: ftp://example.com/c.txt
        """,
    )
    with pytest.raises(UserFeedError) as excinfo:
        _load(p, strict=True)
    assert len(excinfo.value.issues) == 3


def test_strict_file_level_error_raises(tmp_path):
    p = tmp_path / "user-feeds.yaml"
    p.write_text("feeds: [unterminated\n", encoding="utf-8")
    with pytest.raises(UserFeedError):
        _load(p, strict=True)


def test_strict_missing_file_does_not_raise(tmp_path):
    result = _load(tmp_path / "nope.yaml", strict=True)
    assert result.specs == []
    assert result.issues == []
