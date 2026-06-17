"""Tests for the IPv4 IP/CIDR parser in parsers/plaintext.py (parse_ip_text)."""

from __future__ import annotations

import logging

from rpz_factory.models import EntryType, SourceRef
from rpz_factory.parsers.plaintext import parse_ip_text

SRC = SourceRef("user_bad_ips")


def _vals(result):
    return [(e.value, e.entry_type) for e in result.entries]


def test_bare_address_is_ip_and_network_is_cidr():
    result = parse_ip_text("1.2.3.4\n10.0.0.0/8\n", SRC)
    assert _vals(result) == [
        ("1.2.3.4", EntryType.IP),
        ("10.0.0.0/8", EntryType.CIDR),
    ]


def test_cidr_host_bits_are_masked_off():
    # strict=False: 1.2.3.4/24 normalizes to the network 1.2.3.0/24.
    result = parse_ip_text("1.2.3.4/24\n", SRC)
    assert _vals(result) == [("1.2.3.0/24", EntryType.CIDR)]


def test_broad_prefix_is_kept():
    # The old /24 floor was a misdiagnosis; the renderer handles /1-/32.
    result = parse_ip_text("172.16.0.0/16\n", SRC)
    assert _vals(result) == [("172.16.0.0/16", EntryType.CIDR)]


def test_zero_prefix_kept_for_renderer_to_drop():
    # parse_ip_text keeps 0.0.0.0/0; the renderer owns the /0 drop.
    result = parse_ip_text("0.0.0.0/0\n", SRC)
    assert _vals(result) == [("0.0.0.0/0", EntryType.CIDR)]


def test_ipv6_dropped():
    result = parse_ip_text("2001:db8::1\n2001:db8::/32\n1.2.3.4\n", SRC)
    assert _vals(result) == [("1.2.3.4", EntryType.IP)]


def test_garbage_and_bad_prefix_dropped():
    result = parse_ip_text("not-an-ip\n1.2.3.4/33\n9.9.9.9\n", SRC)
    assert _vals(result) == [("9.9.9.9", EntryType.IP)]


def test_comments_and_blanks_stripped():
    text = (
        "# header comment\n"
        "\n"
        "; another comment\n"
        "1.2.3.4  # inline comment\n"
        "5.6.7.8\t; trailing\n"
        "! adblock-style comment\n"
    )
    result = parse_ip_text(text, SRC)
    assert _vals(result) == [
        ("1.2.3.4", EntryType.IP),
        ("5.6.7.8", EntryType.IP),
    ]


def test_dedup():
    result = parse_ip_text("1.2.3.4\n1.2.3.4\n10.0.0.0/8\n10.0.0.0/8\n", SRC)
    assert _vals(result) == [
        ("1.2.3.4", EntryType.IP),
        ("10.0.0.0/8", EntryType.CIDR),
    ]


def test_drop_count_warns_when_drops_exceed_kept(caplog):
    # 1 kept, 3 dropped (2 IPv6 + 1 garbage) -> drops > kept -> WARNING.
    text = "1.2.3.4\n2001:db8::1\nfe80::1\nnope\n"
    with caplog.at_level(logging.WARNING, logger="rpz_factory.parsers.plaintext"):
        parse_ip_text(text, SRC)
    msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("kept 1" in m and "dropped 2 IPv6" in m and "dropped 1 unparseable" in m for m in msgs)


def test_drop_count_stays_info_when_majority_kept(caplog):
    # 3 kept, 1 dropped -> drops < kept -> INFO only, no WARNING.
    text = "1.2.3.4\n5.6.7.8\n9.9.9.9\n2001:db8::1\n"
    with caplog.at_level(logging.INFO, logger="rpz_factory.parsers.plaintext"):
        parse_ip_text(text, SRC)
    assert not any(r.levelno == logging.WARNING for r in caplog.records)
    assert any("kept 3" in r.getMessage() for r in caplog.records if r.levelno == logging.INFO)


def test_drop_count_boundary_equal_stays_info(caplog):
    # 2 kept, 2 dropped -> drops == kept -> strict '>' keeps it at INFO.
    text = "1.2.3.4\n5.6.7.8\n2001:db8::1\ngarbage\n"
    with caplog.at_level(logging.INFO, logger="rpz_factory.parsers.plaintext"):
        parse_ip_text(text, SRC)
    assert not any(r.levelno == logging.WARNING for r in caplog.records)


def test_label_defaults_to_source_value(caplog):
    with caplog.at_level(logging.INFO, logger="rpz_factory.parsers.plaintext"):
        parse_ip_text("1.2.3.4\n", SRC)
    assert any("user_bad_ips" in r.getMessage() for r in caplog.records)
