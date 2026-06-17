"""Tests for the SourceRef identity model (models.py) and its cache round-trip."""

from __future__ import annotations

from rpz_factory.cache import load_cache, write_cache
from rpz_factory.models import EntryType, FetchResult, SourceName, SourceRef, ThreatEntry


def test_sourceref_is_frozen_and_hashable():
    ref = SourceRef("user_my_bad_ips")
    assert ref.value == "user_my_bad_ips"
    # frozen → hashable and usable as a dict/set key
    assert {ref: 1}[SourceRef("user_my_bad_ips")] == 1
    assert SourceRef("a") == SourceRef("a")
    assert SourceRef("a") != SourceRef("b")


def test_threatentry_with_sourceref_is_hashable():
    entry = ThreatEntry(
        value="1.2.3.4",
        entry_type=EntryType.IP,
        source=SourceRef("user_my_bad_ips"),
    )
    # frozen ThreatEntry must stay hashable when stamped with a SourceRef
    assert len({entry, entry}) == 1
    assert entry.source.value == "user_my_bad_ips"


def test_value_attr_is_uniform_across_sourcename_and_sourceref():
    # Every consumer reads `.value`; both identity types expose it the same way.
    builtin = ThreatEntry(value="evil.com", entry_type=EntryType.DOMAIN, source=SourceName.ADGUARD_DNS)
    user = ThreatEntry(value="evil.com", entry_type=EntryType.DOMAIN, source=SourceRef("user_x"))
    assert builtin.source.value == "adguard_dns"
    assert user.source.value == "user_x"


def test_sourceref_round_trips_through_cache(tmp_path):
    cache_dir = str(tmp_path)
    ref = SourceRef("user_my_bad_ips")
    result = FetchResult(source=ref)
    result.entries.append(
        ThreatEntry(value="1.2.3.0/24", entry_type=EntryType.CIDR, source=ref, raw_line="1.2.3.0/24")
    )
    result.entries.append(
        ThreatEntry(value="5.6.7.8", entry_type=EntryType.IP, source=ref, raw_line="5.6.7.8")
    )

    write_cache(cache_dir, result)

    # cache.py keys files by source.value, so a SourceRef loads back the same.
    loaded = load_cache(cache_dir, ref)
    assert loaded is not None
    assert [(e.value, e.entry_type) for e in loaded.entries] == [
        ("1.2.3.0/24", EntryType.CIDR),
        ("5.6.7.8", EntryType.IP),
    ]
    # The reloaded entries carry the SourceRef we passed to load_cache.
    assert all(e.source is ref for e in loaded.entries)
