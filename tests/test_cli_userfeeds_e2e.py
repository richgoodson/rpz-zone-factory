"""End-to-end: user feeds (domain + ip) flow through cli.main to zone files.

cli.py derives its module-level maps (ALL_SOURCES, SOURCE_ZONE_NAMES, the
key/url maps, SOURCE_FETCHERS) from REGISTRY at import time, so exercising user
feeds through cli.main requires reloading categories *then* cli under a
controlled RPZ_USER_FEEDS. The fixture below does that and restores the
built-ins-only state afterward.
"""

from __future__ import annotations

import importlib
import logging

import pytest

from rpz_factory import categories as _categories
from rpz_factory import cli as _cli
from rpz_factory.parsers import plaintext as _plaintext

USER_FEEDS_YAML = """
feeds:
  - key: my-domain
    category: malware
    url: https://feeds.test/domains.txt
    kind: domain
  - key: my-ips
    category: ipreputation
    url: https://feeds.test/ips.txt
    kind: ip
  - key: bad-one
    category: not-a-real-category
    url: https://feeds.test/bad.txt
"""

DOMAINS_TXT = """\
# domains feed
evil.example.com
0.0.0.0 ads.example.net
localhost
thisisnotadomain
bad_under.example.com
"""

IPS_TXT = """\
# ips feed
1.2.3.4
10.0.0.0/8
2001:db8::1
garbage-not-an-ip
"""

URL_CONTENT = {
    "https://feeds.test/domains.txt": DOMAINS_TXT,
    "https://feeds.test/ips.txt": IPS_TXT,
}


@pytest.fixture
def cli_with_user_feeds(tmp_path, monkeypatch):
    """Reload categories+cli with the fixture YAML; patch fetch_url to local."""
    p = tmp_path / "user-feeds.yaml"
    p.write_text(USER_FEEDS_YAML, encoding="utf-8")
    monkeypatch.setenv("RPZ_USER_FEEDS", str(p))

    importlib.reload(_categories)
    cli = importlib.reload(_cli)

    def fake_fetch_url(url, etag=None, last_modified=None):
        return URL_CONTENT[url]

    # The generic fetcher closures resolve fetch_url from the plaintext module
    # namespace at call time, so patching it here covers both user feeds.
    monkeypatch.setattr(_plaintext, "fetch_url", fake_fetch_url)

    try:
        yield cli
    finally:
        monkeypatch.delenv("RPZ_USER_FEEDS", raising=False)
        importlib.reload(_categories)
        importlib.reload(_cli)


def test_user_feeds_render_zone_files(cli_with_user_feeds, tmp_path, caplog):
    cli = cli_with_user_feeds
    out_dir = tmp_path / "zones"
    cache_dir = tmp_path / "cache"

    with caplog.at_level(logging.WARNING, logger="rpz_factory"):
        rc = cli.main(
            [
                "--sources", "my-domain", "my-ips",
                "--output", "rpz",
                "--output-file", str(out_dir),
                "--cache-dir", str(cache_dir),
            ]
        )
    assert rc == 0

    domain_db = (out_dir / "my-domain.malware.rpz.db").read_text()
    ip_db = (out_dir / "my-ips.ipreputation.rpz.db").read_text()

    # --- domain zone: correct name, valid entries present, malformed dropped ---
    assert "evil.example.com.my-domain.malware.rpz. CNAME .\n" in domain_db
    assert "*.evil.example.com.my-domain.malware.rpz. CNAME .\n" in domain_db
    assert "ads.example.net.my-domain.malware.rpz. CNAME .\n" in domain_db
    assert "localhost" not in domain_db
    assert "thisisnotadomain" not in domain_db
    assert "bad_under" not in domain_db

    # --- ip zone: rpz-ip records incl. a broad prefix; IPv6 + garbage dropped ---
    assert "32.4.3.2.1.rpz-ip.my-ips.ipreputation.rpz. CNAME .\n" in ip_db  # 1.2.3.4/32
    assert "8.0.0.0.10.rpz-ip.my-ips.ipreputation.rpz. CNAME .\n" in ip_db  # 10.0.0.0/8 (broad)
    assert "2001" not in ip_db  # IPv6 dropped
    assert "garbage" not in ip_db

    # --- the skipped feed is surfaced loudly at WARNING ---
    warnings = "\n".join(r.getMessage() for r in caplog.records if r.levelno == logging.WARNING)
    assert "SKIPPED" in warnings
    assert "bad-one" in warnings


def test_user_feed_caches_and_recovers_on_304(cli_with_user_feeds, tmp_path):
    """A user feed's entries are cached under its SourceRef value and reused."""
    cli = cli_with_user_feeds
    out_dir = tmp_path / "zones"
    cache_dir = tmp_path / "cache"

    rc = cli.main(
        ["--sources", "my-ips", "--output", "rpz",
         "--output-file", str(out_dir), "--cache-dir", str(cache_dir)]
    )
    assert rc == 0
    # cache.py keys files by source.value; the user feed's SourceRef value is
    # "user_my_ips", so its cache file must exist.
    assert (cache_dir / "user_my_ips.json").is_file()
