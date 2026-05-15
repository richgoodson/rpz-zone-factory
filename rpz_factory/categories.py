"""Threat-feed registry: single source of truth for feeds, zones, and categories.

Every feed has:
  - a stable key (used in --sources / CONF_SOURCES, in cache filenames, and
    as a SourceName enum value)
  - a zone filename of the form <feed>.<category>.rpz (or just <feed>.rpz
    for policy zones like the allowlist), so the SOA returned in synthesized
    NXDOMAIN responses tells the operator the block category at a glance
  - exactly one category from CATEGORIES

The shell layer (run-rpz.sh) consults this registry via the
`python -m rpz_factory.categories` CLI to expand category selections to
zone lists or feed lists. Keeping it in one place avoids drift between
Python and shell layers.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass

# Ordered for display purposes (wizard, --help, summaries).
CATEGORIES: tuple[str, ...] = (
    "malware",
    "ads",
    "tracking",
    "scam",
    "cryptojacking",
    "ipreputation",
    "vulnerabilities",
)


@dataclass(frozen=True)
class FeedSpec:
    """One threat feed."""

    key: str           # CLI/config token, e.g. "urlhaus"
    zone: str          # zone filename without leading path, e.g. "urlhaus.malware.rpz"
    category: str      # one of CATEGORIES, or "policy" for allowlist
    enum_value: str    # SourceName enum value, e.g. "abusech_urlhaus"
    url: str           # primary feed URL


# The allowlist is a policy zone (passthru), not a category-blocked zone.
# It still appears here so the registry is the complete picture of what
# zones the system manages.
_ALLOWLIST = FeedSpec(
    key="allowlist",
    zone="allowlist.rpz",
    category="policy",
    enum_value="allowlist",
    url="",  # local file, not HTTP
)

_FEEDS: tuple[FeedSpec, ...] = (
    FeedSpec(
        key="urlhaus",
        zone="urlhaus.malware.rpz",
        category="malware",
        enum_value="abusech_urlhaus",
        url="https://urlhaus.abuse.ch/downloads/rpz/",
    ),
    FeedSpec(
        key="cisa",
        zone="cisa-kev.vulnerabilities.rpz",
        category="vulnerabilities",
        enum_value="cisa_kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    FeedSpec(
        key="drop",
        zone="spamhaus-drop.ipreputation.rpz",
        category="ipreputation",
        enum_value="spamhaus_drop",
        url="https://www.spamhaus.org/drop/drop.txt",
    ),
    FeedSpec(
        key="scamsniffer",
        zone="scamsniffer.scam.rpz",
        category="scam",
        enum_value="scamsniffer",
        url="https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json",
    ),
    FeedSpec(
        key="cryptoscamdb",
        zone="cryptoscamdb.scam.rpz",
        category="scam",
        enum_value="cryptoscamdb",
        url="https://raw.githubusercontent.com/CryptoScamDB/blacklist/master/data/urls.yaml",
    ),
    FeedSpec(
        key="et-compromised",
        zone="et-compromised.ipreputation.rpz",
        category="ipreputation",
        enum_value="et_compromised_ips",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    ),
    FeedSpec(
        key="adguard-dns",
        zone="adguard-dns.ads.rpz",
        category="ads",
        enum_value="adguard_dns",
        url="https://v.firebog.net/hosts/AdguardDNS.txt",
    ),
    FeedSpec(
        key="anudeepnd",
        zone="anudeepnd.ads.rpz",
        category="ads",
        enum_value="anudeepnd",
        url="https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt",
    ),
    FeedSpec(
        key="easyprivacy",
        zone="easyprivacy.tracking.rpz",
        category="tracking",
        enum_value="easyprivacy",
        url="https://v.firebog.net/hosts/Easyprivacy.txt",
    ),
    FeedSpec(
        key="antimalware-hosts",
        zone="antimalware-hosts.malware.rpz",
        category="malware",
        enum_value="antimalware_hosts",
        url="https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
    ),
    FeedSpec(
        key="prigent-crypto",
        zone="prigent-crypto.cryptojacking.rpz",
        category="cryptojacking",
        enum_value="prigent_crypto",
        url="https://v.firebog.net/hosts/Prigent-Crypto.txt",
    ),
    FeedSpec(
        key="developerdan",
        zone="developerdan.ads.rpz",
        category="ads",
        enum_value="developerdan",
        url="https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    ),
)

REGISTRY: dict[str, FeedSpec] = {f.key: f for f in _FEEDS}
ALLOWLIST: FeedSpec = _ALLOWLIST


def all_feed_keys() -> list[str]:
    """All non-allowlist feed keys, in registry order."""
    return [f.key for f in _FEEDS]


def feeds_for_categories(cats: list[str]) -> list[str]:
    """Feed keys whose category is in `cats`. Order: registry order."""
    cs = set(cats)
    return [f.key for f in _FEEDS if f.category in cs]


def zones_for_categories(cats: list[str]) -> list[str]:
    """Zone filenames whose category is in `cats`. Order: registry order."""
    cs = set(cats)
    return [f.zone for f in _FEEDS if f.category in cs]


def zone_for_feed(key: str) -> str:
    return REGISTRY[key].zone


def category_for_feed(key: str) -> str:
    return REGISTRY[key].category


def feeds_in_category(cat: str) -> list[str]:
    return [f.key for f in _FEEDS if f.category == cat]


def resolve_selection(
    *,
    categories: list[str] | None = None,
    sources: list[str] | None = None,
    extra: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[str]:
    """Resolve a selection spec to a deduplicated, ordered list of feed keys.

    Logic:
      - If `categories` is given, start with feeds_for_categories(categories).
      - Else if `sources` is given, start with that exact list.
      - Else start with all_feed_keys() (the default).
      - Add anything in `extra`.
      - Subtract anything in `exclude`.
      - Preserve registry order in the final output.

    Unknown keys raise ValueError.
    """
    known = set(REGISTRY)

    def _check(items: list[str], label: str) -> None:
        bad = [x for x in items if x not in known]
        if bad:
            raise ValueError(f"unknown feed keys in {label}: {bad}")

    if categories:
        bad_cats = [c for c in categories if c not in CATEGORIES]
        if bad_cats:
            raise ValueError(f"unknown categories: {bad_cats}")
        selected = set(feeds_for_categories(categories))
    elif sources:
        _check(sources, "sources")
        selected = set(sources)
    else:
        selected = set(all_feed_keys())

    if extra:
        _check(extra, "extra")
        selected.update(extra)

    if exclude:
        _check(exclude, "exclude")
        selected.difference_update(exclude)

    return [f.key for f in _FEEDS if f.key in selected]


def _cli(argv: list[str] | None = None) -> int:
    """Shell-friendly CLI for run-rpz.sh.

    Examples:
      python -m rpz_factory.categories list-categories
      python -m rpz_factory.categories list-feeds
      python -m rpz_factory.categories list-feeds --category malware
      python -m rpz_factory.categories list-zones --categories malware ads
      python -m rpz_factory.categories resolve --categories malware --extra easyprivacy
      python -m rpz_factory.categories zone-for urlhaus
      python -m rpz_factory.categories category-for urlhaus
    """
    p = argparse.ArgumentParser(prog="rpz_factory.categories")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list-categories", help="print all category names, one per line")

    p_feeds = sub.add_parser("list-feeds", help="print feed keys, one per line")
    p_feeds.add_argument("--category", help="filter to one category")

    p_zones = sub.add_parser("list-zones", help="print zone filenames, one per line")
    p_zones.add_argument("--categories", nargs="+")
    p_zones.add_argument("--include-allowlist", action="store_true")

    p_resolve = sub.add_parser(
        "resolve",
        help="apply category/source/extra/exclude logic and print resulting feed keys",
    )
    p_resolve.add_argument("--categories", nargs="+", default=[])
    p_resolve.add_argument("--sources", nargs="+", default=[])
    p_resolve.add_argument("--extra", nargs="+", default=[])
    p_resolve.add_argument("--exclude", nargs="+", default=[])
    p_resolve.add_argument(
        "--as-zones",
        action="store_true",
        help="print zone filenames instead of feed keys",
    )

    p_zf = sub.add_parser("zone-for", help="print zone filename for a feed key")
    p_zf.add_argument("feed")

    p_cf = sub.add_parser("category-for", help="print category for a feed key")
    p_cf.add_argument("feed")

    args = p.parse_args(argv)

    if args.cmd == "list-categories":
        for c in CATEGORIES:
            print(c)
        return 0

    if args.cmd == "list-feeds":
        if args.category:
            if args.category not in CATEGORIES:
                print(f"unknown category: {args.category}", file=sys.stderr)
                return 1
            for k in feeds_in_category(args.category):
                print(k)
        else:
            for k in all_feed_keys():
                print(k)
        return 0

    if args.cmd == "list-zones":
        if args.categories:
            zones = zones_for_categories(args.categories)
        else:
            zones = [f.zone for f in _FEEDS]
        if args.include_allowlist:
            zones = [ALLOWLIST.zone, *zones]
        for z in zones:
            print(z)
        return 0

    if args.cmd == "resolve":
        try:
            keys = resolve_selection(
                categories=args.categories or None,
                sources=args.sources or None,
                extra=args.extra or None,
                exclude=args.exclude or None,
            )
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        if args.as_zones:
            for k in keys:
                print(REGISTRY[k].zone)
        else:
            for k in keys:
                print(k)
        return 0

    if args.cmd == "zone-for":
        spec = REGISTRY.get(args.feed)
        if not spec:
            if args.feed == ALLOWLIST.key:
                print(ALLOWLIST.zone)
                return 0
            print(f"unknown feed: {args.feed}", file=sys.stderr)
            return 1
        print(spec.zone)
        return 0

    if args.cmd == "category-for":
        spec = REGISTRY.get(args.feed)
        if not spec:
            if args.feed == ALLOWLIST.key:
                print(ALLOWLIST.category)
                return 0
            print(f"unknown feed: {args.feed}", file=sys.stderr)
            return 1
        print(spec.category)
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(_cli())
