"""HTTP fetch with retry and timeout for each threat intel source."""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 2.0

HEADERS = {
    "User-Agent": "rpz-zone-factory/0.1 (threat-intel aggregator)",
}


def fetch_url(
    url: str,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    backoff: float = DEFAULT_BACKOFF,
    expect_json: bool = False,
) -> str | dict[str, Any]:
    """Fetch a URL with retries and exponential backoff.

    Returns the response text, or parsed JSON if expect_json=True.
    Raises on final failure after all retries.
    """
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            logger.debug("Fetching %s (attempt %d/%d)", url, attempt, retries)
            resp = requests.get(url, timeout=timeout, headers=HEADERS)
            resp.raise_for_status()
            if expect_json:
                return resp.json()
            return resp.text
        except requests.RequestException as exc:
            last_exc = exc
            logger.warning("Fetch %s attempt %d failed: %s", url, attempt, exc)
            if attempt < retries:
                time.sleep(backoff * attempt)

    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts: {last_exc}")
