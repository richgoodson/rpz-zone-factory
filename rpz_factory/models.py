"""Data models for threat entries and sources."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class EntryType(enum.Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


class SourceName(enum.Enum):
    ABUSECH_URLHAUS = "abusech_urlhaus"
    CISA_KEV = "cisa_kev"
    SPAMHAUS_DROP = "spamhaus_drop"
    SPAMHAUS_DBL = "spamhaus_dbl"
    SCAMSNIFFER = "scamsniffer"
    CRYPTOSCAMDB = "cryptoscamdb"
    ET_COMPROMISED_IPS = "et_compromised_ips"
    ADGUARD_DNS = "adguard_dns"
    ANUDEEPND = "anudeepnd"
    EASYPRIVACY = "easyprivacy"
    ANTIMALWARE_HOSTS = "antimalware_hosts"
    PRIGENT_CRYPTO = "prigent_crypto"
    DEVELOPERDAN = "developerdan"


@dataclass(frozen=True)
class SourceRef:
    """Source identity for an operator-defined (user) feed.

    Built-in feeds carry a `SourceName` enum member; user feeds carry a
    `SourceRef` instead. Every consumer of a source object only ever reads
    `.value`, so the two are interchangeable at every call site. Frozen and
    hashable, so a `ThreatEntry` stamped with a `SourceRef` stays hashable like
    one stamped with a `SourceName`.

    Using a value object rather than dynamically extending the `SourceName`
    enum keeps `models.py` import-pure: it does no config loading, so a
    malformed `user-feeds.yaml` can never make the package unimportable.
    """

    value: str


@dataclass(frozen=True)
class ThreatEntry:
    """A single threat indicator (domain, IP, or CIDR)."""

    value: str
    entry_type: EntryType
    source: SourceName | SourceRef
    raw_line: str = ""

    def normalized_value(self) -> str:
        """Return a lowercase, stripped version for dedup."""
        v = self.value.strip().lower().rstrip(".")
        return v


@dataclass
class FetchResult:
    """Result from fetching a single source."""

    source: SourceName | SourceRef
    entries: list[ThreatEntry] = field(default_factory=list)
    error: str | None = None
    raw_count: int = 0
    not_modified: bool = False


@dataclass
class HttpMeta:
    """HTTP conditional-request metadata for cache persistence."""

    etag: str | None = None
    last_modified: str | None = None
