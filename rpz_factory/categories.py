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
import glob
import os
import sys
from dataclasses import dataclass

from rpz_factory import userfeeds

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
    enum_value: str    # source identity value, e.g. "abusech_urlhaus" or "user_my_feed"
    url: str           # primary feed URL
    kind: str = "domain"  # "domain" or "ip" - selects the generic plaintext parser


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

# abuse.ch retired the keyless URLhaus RPZ endpoint (HTTP 410 since
# 2026-10-21). The replacement export requires a free Auth-Key from
# https://auth.abuse.ch/, substituted into the URL path at fetch time from
# $ABUSECH_AUTH_KEY (see fetcher.AUTH_KEY_PLACEHOLDER). The registry stores
# the template only, so the key never appears in logs, args, or this repo.
# $URLHAUS_RPZ_URL overrides the whole template if the export filename
# differs from this default.
_URLHAUS_DEFAULT_URL = (
    "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/rpz.txt"
)

_BUILTIN_FEEDS: tuple[FeedSpec, ...] = (
    FeedSpec(
        key="urlhaus",
        zone="urlhaus.malware.rpz",
        category="malware",
        enum_value="abusech_urlhaus",
        url=os.environ.get("URLHAUS_RPZ_URL") or _URLHAUS_DEFAULT_URL,
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

ALLOWLIST: FeedSpec = _ALLOWLIST


def _builtin_registry_facts() -> tuple[set[str], set[str]]:
    """Return (built-in keys, built-in zones), each including the allowlist.

    These are the facts user feeds are validated against. Owning them here and
    passing them into userfeeds keeps the dependency arrow one-way
    (categories -> userfeeds) and userfeeds import-pure.
    """
    keys = {f.key for f in _BUILTIN_FEEDS} | {_ALLOWLIST.key}
    zones = {f.zone for f in _BUILTIN_FEEDS} | {_ALLOWLIST.zone}
    return keys, zones


def _load_user_feeds() -> tuple[list[FeedSpec], list[str]]:
    """Validate user-feeds.yaml and return (valid FeedSpecs, issue strings).

    Lenient: never raises, so a malformed config yields built-ins only plus
    recorded issues. categories.py *is* the registry and is imported by both
    cli.py and the shell, so it must stay importable no matter what the file
    contains - a bad feed degrades to a recorded issue, never an exception.
    """
    builtin_keys, builtin_zones = _builtin_registry_facts()
    result = userfeeds.load_user_feeds(
        valid_categories=set(CATEGORIES),
        builtin_keys=builtin_keys,
        builtin_zones=builtin_zones,
    )
    specs = [
        FeedSpec(
            key=s.key,
            zone=s.zone,
            category=s.category,
            enum_value=s.enum_value,
            url=s.url,
            kind=s.kind,
        )
        for s in result.specs
    ]
    return specs, result.issues


# Loaded at import time: categories.py is the registry, and both cli.py and the
# shell need user feeds present in REGISTRY. Built-ins always come first (stable
# order), then any valid user feeds.
_USER_FEEDS, USER_FEED_ISSUES = _load_user_feeds()
_FEEDS: tuple[FeedSpec, ...] = _BUILTIN_FEEDS + tuple(_USER_FEEDS)

REGISTRY: dict[str, FeedSpec] = {f.key: f for f in _FEEDS}


def user_feed_summary() -> str | None:
    """One-line WARNING summary of skipped user feeds, or None if clean.

    Shared by both entry points (cli.main and this module's _cli) so the line
    is identical regardless of how user feeds were loaded. Returns None when
    nothing was skipped - including the common no-user-feeds case.
    """
    if not USER_FEED_ISSUES:
        return None
    reasons = "; ".join(USER_FEED_ISSUES)
    return (
        f"user-feeds: loaded {len(_USER_FEEDS)}, SKIPPED {len(USER_FEED_ISSUES)} "
        f"({reasons}) - run 'validate-feeds'"
    )


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


def _render_zone_block(
    *,
    zone_name: str,
    zone_file: str,
    tsig_key: str | None,
    allow_query_acl: str,
    transfer_acl: str,
    transfer_tsig_key: str | None,
    include_also_notify: bool,
    comment: str | None = None,
) -> str:
    """Return a single named.conf `zone {}` block as a multi-line string."""
    lines: list[str] = []
    if comment:
        lines.append(f"// {comment}")
    lines.append(f'zone "{zone_name}" {{')
    lines.append("    type primary;")
    lines.append(f'    file "{zone_file}";')
    if tsig_key:
        lines.append(f'    allow-update {{ key "{tsig_key}"; }};')
    lines.append(f"    allow-query {{ localhost; {allow_query_acl}; }};")
    if transfer_tsig_key:
        lines.append(f'    allow-transfer {{ key "{transfer_tsig_key}"; }};')
    else:
        lines.append(f"    allow-transfer {{ {transfer_acl}; }};")
    if include_also_notify:
        lines.append("    also-notify { /* secondary IPs */ };")
    lines.append("};")
    return "\n".join(lines)


def render_bind_config(
    *,
    zones: list[str],
    zone_dir: str,
    tsig_key: str | None,
    allow_query_acl: str,
    transfer_acl: str,
    transfer_tsig_key: str | None,
    include_also_notify: bool,
    include_allowlist: bool,
    section: str,
) -> str:
    """Render a named.conf snippet (zone blocks and/or response-policy stanza).

    `zones` should be a list of zone filenames (e.g., 'urlhaus.malware.rpz').
    The allowlist zone is added separately when `include_allowlist` is True; if
    it appears in `zones` it's de-duplicated.

    `section` is one of 'zones', 'policy', 'both'.
    """
    seen: set[str] = set()
    ordered_zones: list[str] = []
    for z in zones:
        if z == ALLOWLIST.zone:
            continue
        if z in seen:
            continue
        seen.add(z)
        ordered_zones.append(z)

    out: list[str] = []
    zone_dir = zone_dir.rstrip("/")

    if section in ("zones", "both"):
        out.append("// Generated by: python -m rpz_factory.categories bind-config")
        if tsig_key:
            out.append("//")
            out.append("// The TSIG key referenced by allow-update must be defined elsewhere")
            out.append("// in named.conf, typically via an include statement at the top level:")
            out.append(f'//   include "/etc/bind/tsig/{tsig_key}.key";')
        out.append("")

        if include_allowlist:
            out.append(
                _render_zone_block(
                    zone_name=ALLOWLIST.zone,
                    zone_file=f"{zone_dir}/{ALLOWLIST.zone}.db",
                    tsig_key=tsig_key,
                    allow_query_acl=allow_query_acl,
                    transfer_acl=transfer_acl,
                    transfer_tsig_key=transfer_tsig_key,
                    include_also_notify=include_also_notify,
                    comment="Allowlist zone: evaluated first, passthru overrides blocks",
                )
            )
            out.append("")

        if ordered_zones:
            out.append("// Threat source zones")
            for z in ordered_zones:
                out.append("")
                out.append(
                    _render_zone_block(
                        zone_name=z,
                        zone_file=f"{zone_dir}/{z}.db",
                        tsig_key=tsig_key,
                        allow_query_acl=allow_query_acl,
                        transfer_acl=transfer_acl,
                        transfer_tsig_key=transfer_tsig_key,
                        include_also_notify=include_also_notify,
                    )
                )

    if section == "both":
        out.append("")
        out.append("")

    if section in ("policy", "both"):
        out.append("// Drop the following response-policy block inside your options { } stanza.")
        out.append("// RPZ zones are evaluated in order; the allowlist goes first with")
        out.append("// `policy passthru` so it can override blocks from subsequent zones.")
        out.append("")
        out.append("options {")
        out.append("    // ... your existing options ...")
        out.append("")
        out.append("    response-policy {")
        if include_allowlist:
            out.append(f'        zone "{ALLOWLIST.zone}" policy passthru;')
        for z in ordered_zones:
            out.append(f'        zone "{z}";')
        out.append("    };")
        out.append("};")

    return "\n".join(out) + "\n"


def _emit_user_feed_issues() -> None:
    """Print the user-feed skip summary to stderr, if any (decision 5)."""
    summary = user_feed_summary()
    if summary:
        print(f"WARNING: {summary}", file=sys.stderr)


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
      python -m rpz_factory.categories bind-config --categories malware ads
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

    p_bc = sub.add_parser(
        "bind-config",
        help="emit named.conf zone {} blocks and response-policy stanza for selected zones",
    )
    p_bc.add_argument("--categories", nargs="+", default=[])
    p_bc.add_argument("--sources", nargs="+", default=[])
    p_bc.add_argument("--extra", nargs="+", default=[])
    p_bc.add_argument("--exclude", nargs="+", default=[])
    p_bc.add_argument(
        "--zone-dir",
        default="/etc/namedb/master/rpz",
        help="directory holding the .db zone files (default: %(default)s)",
    )
    p_bc.add_argument(
        "--tsig-key",
        default="rpz-update",
        help="TSIG key name for allow-update (default: %(default)s). "
        "Pass an empty string to suppress allow-update entirely.",
    )
    p_bc.add_argument(
        "--allow-query-acl",
        default="secondaries",
        help="ACL allowed to query each zone alongside localhost (default: %(default)s)",
    )
    p_bc.add_argument(
        "--transfer-acl",
        default="secondaries",
        help="ACL allowed to AXFR/IXFR each zone (default: %(default)s)",
    )
    p_bc.add_argument(
        "--transfer-tsig-key",
        default=None,
        help="If set, emit TSIG-authenticated allow-transfer using this key name "
        "instead of the ACL",
    )
    p_bc.add_argument(
        "--no-also-notify",
        action="store_true",
        help="Omit the `also-notify { /* secondary IPs */ };` placeholder line",
    )
    p_bc.add_argument(
        "--no-allowlist",
        action="store_true",
        help="Omit the allowlist zone (allowlist.rpz)",
    )
    p_bc.add_argument(
        "--section",
        choices=["zones", "policy", "both"],
        default="both",
        help="Which section(s) to emit (default: %(default)s)",
    )

    sub.add_parser(
        "validate-feeds",
        help="strictly validate user-feeds.yaml; print every problem and exit "
        "non-zero if any (run after editing the file)",
    )

    p_orphans = sub.add_parser(
        "list-orphans",
        help="list live zone files / feed snapshots no longer backed by the "
        "registry (e.g. after removing a user feed); exits non-zero if any",
    )
    p_orphans.add_argument(
        "--zone-dir",
        required=True,
        help="directory holding the live <zone>.db files",
    )
    p_orphans.add_argument(
        "--feeds-dir",
        default=None,
        help="optional directory holding <zone>.list.{previous,current} snapshots",
    )

    args = p.parse_args(argv)

    # Surface skipped user feeds on every shell-facing subcommand except
    # validate-feeds (which prints its own, richer report). Passive WARNING to
    # stderr; never changes the subcommand's own exit code (decision 5).
    if args.cmd != "validate-feeds":
        _emit_user_feed_issues()

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

    if args.cmd == "bind-config":
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
        zones = [REGISTRY[k].zone for k in keys]
        sys.stdout.write(
            render_bind_config(
                zones=zones,
                zone_dir=args.zone_dir,
                tsig_key=args.tsig_key or None,
                allow_query_acl=args.allow_query_acl,
                transfer_acl=args.transfer_acl,
                transfer_tsig_key=args.transfer_tsig_key,
                include_also_notify=not args.no_also_notify,
                include_allowlist=not args.no_allowlist,
                section=args.section,
            )
        )
        return 0

    if args.cmd == "validate-feeds":
        builtin_keys, builtin_zones = _builtin_registry_facts()
        try:
            result = userfeeds.load_user_feeds(
                valid_categories=set(CATEGORIES),
                builtin_keys=builtin_keys,
                builtin_zones=builtin_zones,
                strict=True,
            )
        except userfeeds.UserFeedError as e:
            print(
                f"user-feeds: {len(e.issues)} problem(s) in {userfeeds.default_path()}:",
                file=sys.stderr,
            )
            for issue in e.issues:
                print(f"  - {issue}", file=sys.stderr)
            return 1
        print(f"user-feeds: OK ({len(result.specs)} feed(s) valid)")
        return 0

    if args.cmd == "list-orphans":
        # A zone is "known" if it is still backed by the registry (built-in or
        # a currently-valid user feed) or is the allowlist. Anything live on
        # disk that is not known is an orphan from a removed/renamed feed.
        known_zones = {f.zone for f in _FEEDS} | {ALLOWLIST.zone}
        orphans: list[str] = []

        for path in sorted(glob.glob(os.path.join(args.zone_dir, "*.db"))):
            stem = os.path.basename(path)[:-3]  # strip ".db"
            if stem not in known_zones:
                orphans.append(path)

        if args.feeds_dir:
            snapshots = sorted(
                glob.glob(os.path.join(args.feeds_dir, "*.list.previous"))
                + glob.glob(os.path.join(args.feeds_dir, "*.list.current"))
            )
            for path in snapshots:
                base = os.path.basename(path)
                stem = base
                for suffix in (".list.previous", ".list.current"):
                    if base.endswith(suffix):
                        stem = base[: -len(suffix)]
                        break
                if stem not in known_zones:
                    orphans.append(path)

        for o in orphans:
            print(o)
        return 1 if orphans else 0

    return 1


if __name__ == "__main__":
    sys.exit(_cli())
