"""HTTP fetch with retry and timeout for each threat intel source."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import requests

from rpz_factory import __version__

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 2.0

HEADERS = {
    "User-Agent": f"rpz-zone-factory/{__version__} (threat-intel aggregator)",
}

# Literal placeholder in a feed URL that marks where an auth key must be
# substituted at request time (abuse.ch key-in-path style). URLs are stored
# and logged in template form only; the key never appears in logs or errors.
AUTH_KEY_PLACEHOLDER = "{auth_key}"


def redact(text: str, secret: str | None) -> str:
    """Mask every occurrence of *secret* in *text*.

    Applied to exception strings before they reach a logger or a raised
    error, because requests embeds the full (substituted) URL in its error
    messages and those strings propagate into syslog.
    """
    if secret:
        return text.replace(secret, "***")
    return text


class NotModified(Exception):
    """Raised when the server returns 304 Not Modified."""


@dataclass
class FetchResponse:
    """Wrapper around fetch result with HTTP metadata."""

    body: str | dict[str, Any]
    etag: str | None = None
    last_modified: str | None = None


def fetch_url(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    backoff: float = DEFAULT_BACKOFF,
    expect_json: bool = False,
    etag: str | None = None,
    last_modified: str | None = None,
    auth_key: str | None = None,
) -> str | dict[str, Any]:
    """Fetch a URL with retries and exponential backoff.

    Returns the response text, or parsed JSON if expect_json=True.
    Raises NotModified if the server returns 304.
    Raises RuntimeError on final failure after all retries.

    If *url* contains AUTH_KEY_PLACEHOLDER, *auth_key* is substituted into
    the request URL; otherwise a provided key is sent as an Auth-Key header.
    Either way, *url* (the template) is what gets logged, keyed in the meta
    store, and embedded in raised errors, so the key itself never leaves
    this function except in the HTTP request.
    """
    req_headers = dict(HEADERS)
    if etag:
        req_headers["If-None-Match"] = etag
    if last_modified:
        req_headers["If-Modified-Since"] = last_modified

    request_url = url
    if AUTH_KEY_PLACEHOLDER in url:
        if not auth_key:
            raise RuntimeError(f"URL requires an auth key but none was provided: {url}")
        request_url = url.replace(AUTH_KEY_PLACEHOLDER, auth_key)
    elif auth_key:
        req_headers["Auth-Key"] = auth_key

    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            logger.debug("Fetching %s (attempt %d/%d)", url, attempt, retries)
            resp = requests.get(request_url, timeout=timeout, headers=req_headers)

            if resp.status_code == 304:
                logger.info("Source %s returned 304 Not Modified", url)
                raise NotModified(url)

            resp.raise_for_status()

            # Capture response metadata for caching
            resp_etag = resp.headers.get("ETag")
            resp_last_modified = resp.headers.get("Last-Modified")

            if expect_json:
                body = resp.json()
            else:
                body = resp.text

            # Stash metadata on the response for callers that need it
            _last_fetch_meta[url] = FetchResponse(
                body=body, etag=resp_etag, last_modified=resp_last_modified
            )

            return body
        except NotModified:
            raise
        except requests.RequestException as exc:
            last_exc = exc
            logger.warning(
                "Fetch %s attempt %d failed: %s", url, attempt, redact(str(exc), auth_key)
            )
            if attempt < retries:
                time.sleep(backoff * attempt)

    raise RuntimeError(
        f"Failed to fetch {url} after {retries} attempts: {redact(str(last_exc), auth_key)}"
    )


# Module-level store for HTTP metadata from the last fetch per URL.
# Parsers call get_last_fetch_meta() after a successful fetch_url() to
# retrieve ETag/Last-Modified without changing their return signatures.
_last_fetch_meta: dict[str, FetchResponse] = {}


def get_last_fetch_meta(url: str) -> FetchResponse | None:
    """Return HTTP metadata from the last successful fetch of *url*."""
    return _last_fetch_meta.get(url)
