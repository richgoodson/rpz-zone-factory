"""Tests for user-feed merge + the validate-feeds / list-orphans subcommands."""

from __future__ import annotations

import contextlib
import importlib
import os
import textwrap

from rpz_factory import categories as _categories


@contextlib.contextmanager
def categories_with_feeds(tmp_path, yaml_text):
    """Reload categories with RPZ_USER_FEEDS pointed at a temp file.

    User feeds are merged at import time, so exercising the merge / the
    import-time USER_FEED_ISSUES requires a fresh module load. Restores the
    built-ins-only state on exit.
    """
    p = tmp_path / "user-feeds.yaml"
    p.write_text(textwrap.dedent(yaml_text), encoding="utf-8")
    old = os.environ.get("RPZ_USER_FEEDS")
    os.environ["RPZ_USER_FEEDS"] = str(p)
    try:
        yield importlib.reload(_categories)
    finally:
        if old is None:
            os.environ.pop("RPZ_USER_FEEDS", None)
        else:
            os.environ["RPZ_USER_FEEDS"] = old
        importlib.reload(_categories)  # restore built-ins-only registry


# --------------------------------------------------------------------------- #
# Registry merge
# --------------------------------------------------------------------------- #


def test_valid_user_feed_merged_into_registry(tmp_path):
    with categories_with_feeds(
        tmp_path,
        """
        feeds:
          - key: my-bad-ips
            category: ipreputation
            url: https://example.com/bad-ips.txt
            kind: ip
        """,
    ) as cats:
        assert cats.USER_FEED_ISSUES == []
        assert "my-bad-ips" in cats.REGISTRY
        spec = cats.REGISTRY["my-bad-ips"]
        assert spec.zone == "my-bad-ips.ipreputation.rpz"
        assert spec.kind == "ip"
        assert spec.enum_value == "user_my_bad_ips"
        # picked up by the registry-derived helpers for free
        assert "my-bad-ips" in cats.all_feed_keys()
        assert "my-bad-ips" in cats.feeds_for_categories(["ipreputation"])
        assert cats.zone_for_feed("my-bad-ips") == "my-bad-ips.ipreputation.rpz"
        # built-ins still present and ordered first
        assert "urlhaus" in cats.REGISTRY
        assert cats.all_feed_keys()[-1] == "my-bad-ips"


def test_builtin_feeds_default_kind_is_domain():
    assert _categories.REGISTRY["urlhaus"].kind == "domain"


def test_invalid_user_feed_absent_and_recorded(tmp_path):
    with categories_with_feeds(
        tmp_path,
        """
        feeds:
          - key: good-one
            category: ads
            url: https://example.com/a.txt
          - key: bad-cat
            category: nope
            url: https://example.com/b.txt
        """,
    ) as cats:
        assert "good-one" in cats.REGISTRY
        assert "bad-cat" not in cats.REGISTRY
        assert len(cats.USER_FEED_ISSUES) == 1
        assert "unknown category" in cats.USER_FEED_ISSUES[0]

        summary = cats.user_feed_summary()
        assert summary is not None
        assert "loaded 1" in summary
        assert "SKIPPED 1" in summary
        assert "validate-feeds" in summary


def test_no_user_feeds_means_clean_summary():
    # Built-ins-only state (restored): nothing skipped -> no summary.
    assert _categories.USER_FEED_ISSUES == []
    assert _categories.user_feed_summary() is None


# --------------------------------------------------------------------------- #
# validate-feeds subcommand (re-reads the file at call time; no reload needed)
# --------------------------------------------------------------------------- #


def test_validate_feeds_clean_exits_zero(tmp_path, capsys, monkeypatch):
    p = tmp_path / "user-feeds.yaml"
    p.write_text(
        "feeds:\n  - key: ok\n    category: ads\n    url: https://example.com/a.txt\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RPZ_USER_FEEDS", str(p))
    rc = _categories._cli(["validate-feeds"])
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_validate_feeds_reports_all_problems_and_exits_nonzero(tmp_path, capsys, monkeypatch):
    p = tmp_path / "user-feeds.yaml"
    p.write_text(
        textwrap.dedent(
            """
            feeds:
              - key: bad_key
                category: ads
                url: https://example.com/a.txt
              - key: badcat
                category: nope
                url: https://example.com/b.txt
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("RPZ_USER_FEEDS", str(p))
    rc = _categories._cli(["validate-feeds"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "2 problem(s)" in err
    assert "DNS-safe" in err
    assert "unknown category" in err


def test_validate_feeds_missing_file_exits_zero(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("RPZ_USER_FEEDS", str(tmp_path / "nope.yaml"))
    rc = _categories._cli(["validate-feeds"])
    assert rc == 0
    assert "0 feed(s) valid" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# list-orphans subcommand (uses the import-time registry)
# --------------------------------------------------------------------------- #


def test_list_orphans_flags_unknown_db_only(tmp_path, capsys):
    zd = tmp_path / "zones"
    zd.mkdir()
    (zd / "urlhaus.malware.rpz.db").write_text("x")  # built-in -> known
    (zd / "allowlist.rpz.db").write_text("x")  # allowlist -> known
    (zd / "removed-feed.ipreputation.rpz.db").write_text("x")  # orphan

    rc = _categories._cli(["list-orphans", "--zone-dir", str(zd)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "removed-feed.ipreputation.rpz.db" in out
    assert "urlhaus" not in out
    assert "allowlist" not in out


def test_list_orphans_clean_exits_zero(tmp_path, capsys):
    zd = tmp_path / "zones"
    zd.mkdir()
    (zd / "urlhaus.malware.rpz.db").write_text("x")
    rc = _categories._cli(["list-orphans", "--zone-dir", str(zd)])
    assert rc == 0
    assert capsys.readouterr().out == ""


def test_list_orphans_flags_snapshot_files(tmp_path, capsys):
    zd = tmp_path / "zones"
    zd.mkdir()
    fd = tmp_path / "feeds"
    fd.mkdir()
    (fd / "removed.ipreputation.rpz.list.previous").write_text("x")  # orphan
    (fd / "urlhaus.malware.rpz.list.current").write_text("x")  # known

    rc = _categories._cli(["list-orphans", "--zone-dir", str(zd), "--feeds-dir", str(fd)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "removed.ipreputation.rpz.list.previous" in out
    assert "urlhaus" not in out


# --------------------------------------------------------------------------- #
# Both-entry-point summary: the module CLI is loud on skipped feeds too
# --------------------------------------------------------------------------- #


def test_module_cli_emits_skip_summary_on_resolve(tmp_path, capsys):
    with categories_with_feeds(
        tmp_path,
        """
        feeds:
          - key: bad-cat
            category: nope
            url: https://example.com/b.txt
        """,
    ) as cats:
        rc = cats._cli(["resolve"])
        captured = capsys.readouterr()
        assert rc == 0  # passive summary never changes the subcommand exit code
        assert "SKIPPED" in captured.err
        assert "bad-cat" in captured.err


def test_module_cli_silent_when_clean(tmp_path, capsys):
    with categories_with_feeds(
        tmp_path,
        """
        feeds:
          - key: good-one
            category: ads
            url: https://example.com/a.txt
        """,
    ) as cats:
        rc = cats._cli(["resolve"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "SKIPPED" not in captured.err
