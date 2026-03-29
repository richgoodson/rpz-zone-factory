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
    SPAMHAUS_EDROP = "spamhaus_edrop"
    SPAMHAUS_DBL = "spamhaus_dbl"


@dataclass(frozen=True)
class ThreatEntry:
    """A single threat indicator (domain, IP, or CIDR)."""

    value: str
    entry_type: EntryType
    source: SourceName
    raw_line: str = ""

    def normalized_value(self) -> str:
        """Return a lowercase, stripped version for dedup."""
        v = self.value.strip().lower().rstrip(".")
        return v


@dataclass
class FetchResult:
    """Result from fetching a single source."""

    source: SourceName
    entries: list[ThreatEntry] = field(default_factory=list)
    error: str | None = None
    raw_count: int = 0
