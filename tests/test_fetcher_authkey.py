"""Auth-key handling in fetcher.py and the urlhaus parser.

Covers the October 2026 abuse.ch migration: key-in-path substitution,
template-form logging/meta-keying, redaction of the key in errors, and the
parser's clear failure when ABUSECH_AUTH_KEY is absent. No network: requests
is mocked.
"""

from __future__ import annotations

from unittest import mock

import pytest
import requests

from rpz_factory import fetcher
from rpz_factory.fetcher import AUTH_KEY_PLACEHOLDER, fetch_url, redact
from rpz_factory.parsers import abusech

TEMPLATE = "https://example.test/v2/files/exports/{auth_key}/feed.txt"
KEY = "sekrit-key-42"


def _resp(status=200, text="body", headers=None):
    r = mock.Mock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    r.raise_for_status = mock.Mock()
    return r


class TestRedact:
    def test_masks_secret(self):
        assert redact(f"err at https://x/{KEY}/f", KEY) == "err at https://x/***/f"

    def test_none_secret_is_noop(self):
        assert redact("unchanged", None) == "unchanged"


class TestFetchUrlAuthKey:
    def test_placeholder_without_key_raises_before_any_request(self):
        with mock.patch.object(fetcher.requests, "get") as get:
            with pytest.raises(RuntimeError, match=r"\{auth_key\}"):
                fetch_url(TEMPLATE)
            get.assert_not_called()

    def test_key_substituted_into_request_url(self):
        with mock.patch.object(fetcher.requests, "get", return_value=_resp()) as get:
            fetch_url(TEMPLATE, auth_key=KEY)
        requested = get.call_args.args[0]
        assert KEY in requested
        assert AUTH_KEY_PLACEHOLDER not in requested

    def test_meta_store_keyed_by_template(self):
        headers = {"ETag": "abc123"}
        with mock.patch.object(fetcher.requests, "get", return_value=_resp(headers=headers)):
            fetch_url(TEMPLATE, auth_key=KEY)
        meta = fetcher.get_last_fetch_meta(TEMPLATE)
        assert meta is not None and meta.etag == "abc123"

    def test_key_without_placeholder_sent_as_header(self):
        with mock.patch.object(fetcher.requests, "get", return_value=_resp()) as get:
            fetch_url("https://example.test/plain.txt", auth_key=KEY)
        assert get.call_args.kwargs["headers"]["Auth-Key"] == KEY

    def test_error_and_logs_never_contain_key(self, caplog):
        exc = requests.RequestException(f"401 for url: https://example.test/{KEY}/feed.txt")
        with mock.patch.object(fetcher.requests, "get", side_effect=exc):
            with mock.patch.object(fetcher.time, "sleep"):
                with pytest.raises(RuntimeError) as ei:
                    fetch_url(TEMPLATE, auth_key=KEY, retries=2)
        assert KEY not in str(ei.value)
        assert "***" in str(ei.value)
        assert KEY not in caplog.text


class TestUrlhausParser:
    def test_missing_key_returns_actionable_error_without_fetching(self, monkeypatch):
        monkeypatch.delenv(abusech.AUTH_KEY_ENV, raising=False)
        with mock.patch.object(fetcher.requests, "get") as get:
            result = abusech.fetch_and_parse()
        get.assert_not_called()
        assert result.error is not None
        assert abusech.AUTH_KEY_ENV in result.error
        assert "auth.abuse.ch" in result.error

    def test_key_from_env_reaches_request(self, monkeypatch):
        monkeypatch.setenv(abusech.AUTH_KEY_ENV, KEY)
        body = "bad.example.com CNAME .\n"
        with mock.patch.object(fetcher.requests, "get", return_value=_resp(text=body)) as get:
            result = abusech.fetch_and_parse()
        assert KEY in get.call_args.args[0]
        assert result.error is None
        assert [e.value for e in result.entries] == ["bad.example.com"]
