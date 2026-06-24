"""CLI entrypoint for rpz-zone-factory."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from rpz_factory import __version__
from rpz_factory.cache import load_cache, load_http_meta, write_cache, write_http_meta
from rpz_factory.categories import (
    CATEGORIES,
    REGISTRY,
    all_feed_keys,
    resolve_selection,
    user_feed_summary,
)
from rpz_factory.fetcher import get_last_fetch_meta
from rpz_factory.filters import filter_entries
from rpz_factory.models import FetchResult, HttpMeta, SourceName, SourceRef, ThreatEntry
from rpz_factory.parsers import (
    abusech,
    cisa,
    cryptoscamdb,
    emergingthreats,
    plaintext,
    scamsniffer,
    spamhaus,
)
from rpz_factory.renderers import pihole, rpz
from rpz_factory.renderers.rpz import compute_next_serial

# Exit code 3 signals "no upstream changes; nothing rendered". Distinct
# from 0 (success, output written) and 1 (error). Deliberately NOT 2, which
# argparse reserves for usage errors (bad/unknown flags) and exits with via
# SystemExit; sharing 2 would make a config-driven arg mistake masquerade as a
# clean no-op in run-rpz.sh. run-rpz.sh treats 3 as a successful no-op and
# skips post-processing (validation, IXFR, reload, seeding).
EXIT_NO_CHANGES = 3

ALL_SOURCES = all_feed_keys()

# Per-source RPZ zone names (used with --per-source). Drops the trailing
# ".db" - the shell layer adds it. Derived from the categories registry.
SOURCE_ZONE_NAMES = {key: spec.zone for key, spec in REGISTRY.items()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rpz-zone-factory",
        description="Fetch threat intel and generate RPZ zone files or Pi-hole blocklists.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--output",
        choices=["rpz", "pihole"],
        default="rpz",
        help="Output format (default: rpz)",
    )
    parser.add_argument(
        "--output-file",
        default=None,
        help="For --output rpz, the directory that will hold one zone file "
             "per source. For --output pihole, the path of the flat blocklist "
             "file. Default: stdout (Pi-hole only; RPZ requires a directory).",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        default=None,
        choices=ALL_SOURCES,
        metavar="FEED",
        help=(
            "Specific feed keys to fetch (default: all, or all feeds in "
            "categories given via --categories). "
            f"Available: {' '.join(ALL_SOURCES)}"
        ),
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        choices=list(CATEGORIES),
        metavar="CATEGORY",
        help=(
            "Fetch all feeds whose category is in this list. Combine with "
            "--sources to add individual feeds outside the chosen categories. "
            f"Available: {' '.join(CATEGORIES)}"
        ),
    )
    parser.add_argument(
        "--exclude-sources",
        nargs="+",
        default=None,
        choices=ALL_SOURCES,
        metavar="FEED",
        help="Drop these feed keys from the resolved selection.",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Cache directory for stale-data preservation (default: {RPZ_DIR}/.cache)",
    )
    parser.add_argument(
        "--allowlist",
        default=None,
        help="Path to allowlist file (one domain per line). Generates "
             "allowlist.rpz.db alongside the threat zones (RPZ output only).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Bypass the 'all sources unchanged (304)' fast-path and always "
             "render. Useful after manual zone edits or for debugging.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)",
    )
    return parser


def _configure_logging(verbosity: int) -> None:
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


SOURCE_FETCHERS = {
    "urlhaus": abusech.fetch_and_parse,
    "cisa": cisa.fetch_and_parse,
    "drop": spamhaus.fetch_drop,
    "scamsniffer": scamsniffer.fetch_and_parse,
    "cryptoscamdb": cryptoscamdb.fetch_and_parse,
    "et-compromised": emergingthreats.fetch_and_parse,
    "adguard-dns": plaintext.make_fetcher(
        REGISTRY["adguard-dns"].url, SourceName.ADGUARD_DNS, label="AdGuard DNS"
    ),
    "anudeepnd": plaintext.make_fetcher(
        REGISTRY["anudeepnd"].url, SourceName.ANUDEEPND, label="anudeepND adservers"
    ),
    "easyprivacy": plaintext.make_fetcher(
        REGISTRY["easyprivacy"].url, SourceName.EASYPRIVACY, label="EasyPrivacy"
    ),
    "antimalware-hosts": plaintext.make_fetcher(
        REGISTRY["antimalware-hosts"].url,
        SourceName.ANTIMALWARE_HOSTS,
        label="AntiMalwareHosts",
    ),
    "prigent-crypto": plaintext.make_fetcher(
        REGISTRY["prigent-crypto"].url,
        SourceName.PRIGENT_CRYPTO,
        label="Prigent Crypto",
    ),
    "developerdan": plaintext.make_fetcher(
        REGISTRY["developerdan"].url,
        SourceName.DEVELOPERDAN,
        label="developerdan ads-and-tracking",
    ),
}

# URLs per source (for HTTP meta lookup after fetch). Derived from registry.
_SOURCE_URLS = {key: spec.url for key, spec in REGISTRY.items() if spec.url}

# Map source keys to SourceName enum values for cache lookups. Derived
# from registry.
_SOURCE_KEY_TO_NAME = {key: spec.enum_value for key, spec in REGISTRY.items()}

# Reverse mapping: SourceName enum value -> source key
_SOURCE_NAME_TO_KEY = {v: k for k, v in _SOURCE_KEY_TO_NAME.items()}


def _source_obj(enum_value: str):
    """Resolve a source identity value to its source object.

    Built-in values map to a SourceName enum member; user-feed values (which
    are not enum members) fall back to a SourceRef. Both expose `.value`, so
    every downstream consumer (cache, filters, grouping) is unaffected.
    """
    try:
        return SourceName(enum_value)
    except ValueError:
        return SourceRef(enum_value)


def _fetcher_for(key: str):
    """Return the fetch_and_parse callable for a feed key.

    Built-ins have a pre-built entry in SOURCE_FETCHERS. User feeds are not in
    that table, so build a generic plaintext fetcher on the fly from their
    registry spec (URL + kind). This is the edit that lets a user feed actually
    fetch - without it the bare SOURCE_FETCHERS lookup KeyErrors on any user
    feed.
    """
    if key in SOURCE_FETCHERS:
        return SOURCE_FETCHERS[key]
    spec = REGISTRY[key]
    return plaintext.make_fetcher(
        spec.url, _source_obj(spec.enum_value), label=key, kind=spec.kind
    )


def _resolve_live_zone_path(output_dir: str, filename: str) -> str:
    """Return the path to the currently-live zone file for serial lookup.

    When checkzone/compilezone is enabled, run-rpz.sh passes --output-file as
    <real_dir>/.tmp so Python writes fresh zones to the staging subdirectory.
    In that case the live zone file is at <real_dir>/<filename>.

    When checkzone is disabled, output_dir IS the real directory and the live
    file is at <output_dir>/<filename> - but that's the same file we're about
    to write. The caller must read the serial BEFORE opening for write.
    """
    # Detect the ".tmp" staging subdirectory convention.
    if os.path.basename(output_dir.rstrip("/")) == ".tmp":
        real_dir = os.path.dirname(output_dir.rstrip("/"))
        return os.path.join(real_dir, filename)
    return os.path.join(output_dir, filename)


def _parse_allowlist_file(path: str) -> list[str]:
    """Parse an allowlist file. Returns list of domains (lowercase, stripped)."""
    domains = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip trailing dot and lowercase
            domain = line.lower().rstrip(".")
            if domain:
                domains.append(domain)
    return domains


def _render_allowlist_zone(
    domains: list[str],
    zone_name: str = "allowlist.rpz",
    serial: int | str | None = None,
) -> str:
    """Render an allowlist zone file with passthru CNAME records."""
    import datetime
    from io import StringIO

    if serial is None:
        serial = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H")
    buf = StringIO()

    buf.write(f"; RPZ allowlist zone file generated by rpz-zone-factory\n")
    buf.write(f"; Zone: {zone_name}\n")
    buf.write(f"; Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
    buf.write(f"; Entries: {len(domains)}\n")
    buf.write(";\n\n")

    buf.write("$TTL 300\n\n")

    buf.write(f"@ IN SOA {zone_name}. hostmaster.{zone_name}. (\n")
    buf.write(f"    {serial}  ; serial\n")
    buf.write(f"    3600       ; refresh\n")
    buf.write(f"    600        ; retry\n")
    buf.write(f"    604800     ; expire\n")
    buf.write(f"    60         ; minimum TTL\n")
    buf.write(")\n\n")

    buf.write(f"@ IN NS LOCALHOST.\n\n")

    buf.write("; --- Allowlist entries (passthru) ---\n\n")

    for domain in sorted(set(domains)):
        buf.write(f"{domain}.{zone_name}. CNAME rpz-passthru.\n")
        buf.write(f"*.{domain}.{zone_name}. CNAME rpz-passthru.\n")

    return buf.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    logger = logging.getLogger("rpz_factory")

    # Surface any skipped user feeds once, loudly, at WARNING - visible even at
    # the default (non-verbose) level so a dropped feed never goes silent in
    # cron mail (decision 5). The categories module CLI emits the same line
    # independently for shell-driven invocations.
    _uf_summary = user_feed_summary()
    if _uf_summary:
        logger.warning(_uf_summary)

    # Resolve --sources / --categories / --exclude-sources into the final
    # ordered feed list. Stored back on args.sources for downstream code.
    # When both --categories and --sources are given, the explicit feed
    # list adds to the category selection (e.g. "malware category PLUS
    # this one extra feed"). When only --sources is given, it's the
    # exact selection. When only --categories is given, that's the
    # selection.
    try:
        if args.categories and args.sources:
            args.sources = resolve_selection(
                categories=args.categories,
                extra=args.sources,
                exclude=args.exclude_sources,
            )
        else:
            args.sources = resolve_selection(
                categories=args.categories,
                sources=args.sources,
                exclude=args.exclude_sources,
            )
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    if not args.sources:
        print(
            "ERROR: feed selection is empty (after applying --categories/--sources/--exclude-sources)",
            file=sys.stderr,
        )
        return 1
    logger.info("Resolved feed selection: %s", " ".join(args.sources))

    # Resolve cache directory
    cache_dir = args.cache_dir
    if cache_dir is None:
        rpz_dir = os.environ.get("RPZ_DIR", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        cache_dir = os.path.join(rpz_dir, ".cache")

    # Fetch from all requested sources
    all_entries: list[ThreatEntry] = []
    errors: list[str] = []
    not_modified_sources: list[str] = []
    # Track sources that hit an error (or exception) so the all-304
    # fast-path doesn't fire when something genuinely went wrong upstream.
    errored_sources: set[str] = set()

    for source_key in args.sources:
        fetcher = _fetcher_for(source_key)
        logger.info("Fetching source: %s", source_key)

        # Load HTTP conditional-request metadata from cache
        source_enum_value = _SOURCE_KEY_TO_NAME.get(source_key)
        http_meta: HttpMeta | None = None
        if source_enum_value:
            try:
                source_enum = _source_obj(source_enum_value)
                http_meta = load_http_meta(cache_dir, source_enum)
            except ValueError:
                pass

        # Build conditional kwargs
        fetch_kwargs: dict[str, str | None] = {}
        if http_meta:
            fetch_kwargs["etag"] = http_meta.etag
            fetch_kwargs["last_modified"] = http_meta.last_modified

        try:
            result: FetchResult = fetcher(**fetch_kwargs)

            if result.not_modified:
                # 304 - use cached entries
                #
                # ponytail: this eager cache load is wasted on a steady-state
                # all-304 run, where _run_per_source skips every zone whose live
                # .db already exists and never touches these entries. Accepted:
                # no-op runs are network-bound (13 sequential conditional GETs
                # dominate wall-clock), so deserializing the caches costs CPU and
                # transient memory but not latency. The cache is genuinely needed
                # only when a 304 source's live zone is missing (seed case). To
                # eliminate the waste, defer load_cache() into _run_per_source so
                # it runs only for zones that actually render - revisit if CPU or
                # peak memory on no-op runs ever becomes a concern.
                logger.info("Source %s: not modified (304), using cache", source_key)
                not_modified_sources.append(source_key)
                if source_enum_value:
                    try:
                        source_enum = _source_obj(source_enum_value)
                        cached = load_cache(cache_dir, source_enum)
                        if cached:
                            all_entries.extend(cached.entries)
                            logger.info(
                                "Source %s: %d entries loaded from cache (304)",
                                source_key,
                                len(cached.entries),
                            )
                        else:
                            logger.warning(
                                "Source %s: 304 but no cache available", source_key
                            )
                    except ValueError:
                        pass
            elif result.error:
                errors.append(f"{source_key}: {result.error}")
                errored_sources.add(source_key)
                logger.warning("Source %s had error: %s", source_key, result.error)
                # Try cache fallback on error
                cached = load_cache(cache_dir, result.source)
                if cached:
                    all_entries.extend(cached.entries)
                    logger.info(
                        "Source %s: %d entries loaded from cache", source_key, len(cached.entries)
                    )
                else:
                    logger.error("Source %s: no cache available", source_key)
            elif not result.entries:
                logger.warning("Source %s returned no entries", source_key)
                # Try cache fallback on empty result
                cached = load_cache(cache_dir, result.source)
                if cached:
                    all_entries.extend(cached.entries)
                    logger.info(
                        "Source %s: %d entries loaded from cache", source_key, len(cached.entries)
                    )
            else:
                all_entries.extend(result.entries)
                write_cache(cache_dir, result)
                logger.info(
                    "Source %s: %d entries collected", source_key, len(result.entries)
                )
                # Save HTTP metadata for future conditional requests
                source_url = _SOURCE_URLS.get(source_key)
                if source_url:
                    fetch_meta = get_last_fetch_meta(source_url)
                    if fetch_meta and (fetch_meta.etag or fetch_meta.last_modified):
                        write_http_meta(
                            cache_dir,
                            result.source,
                            HttpMeta(
                                etag=fetch_meta.etag,
                                last_modified=fetch_meta.last_modified,
                            ),
                        )
        except Exception as exc:
            errors.append(f"{source_key}: {exc}")
            errored_sources.add(source_key)
            logger.error("Source %s failed: %s", source_key, exc)
            # Try cache fallback on exception
            if source_enum_value:
                try:
                    source_enum = _source_obj(source_enum_value)
                    cached = load_cache(cache_dir, source_enum)
                    if cached:
                        all_entries.extend(cached.entries)
                        logger.info(
                            "Source %s: %d entries loaded from cache", source_key, len(cached.entries)
                        )
                    else:
                        logger.error("Source %s: no cache available", source_key)
                except ValueError:
                    pass

    if not all_entries:
        logger.error("No entries collected from any source")
        print("ERROR: No entries collected. Check network and sources.", file=sys.stderr)
        if errors:
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
        return 1

    # ── All-sources-unchanged fast-path detection ─────────────────────────
    # If every requested source returned 304, no source errored out, and
    # there's an existing live zone we can leave in place, we can skip
    # rendering entirely. --force bypasses this.
    all_unchanged = (
        not args.force
        and len(args.sources) > 0
        and all(s in not_modified_sources for s in args.sources)
        and not errored_sources
    )

    # ── RPZ output: per-source path ───────────────────────────────────────
    if args.output == "rpz":
        return _run_per_source(
            args,
            all_entries,
            errors,
            logger,
            not_modified_sources,
            errored_sources,
        )

    # ── Pi-hole output: single combined flat-file ─────────────────────────
    # Pi-hole consumes one file, so it always renders combined.
    #
    # All-unchanged fast-path: if every source returned 304 with no errors
    # and the live blocklist already exists on disk, skip rendering. Stdout
    # and first-run cases fall through to a normal render.
    _live_path = None
    if args.output_file:
        if args.output_file.endswith(".tmp"):
            _live_path = args.output_file[:-4]
        else:
            _live_path = args.output_file

    if (
        all_unchanged
        and _live_path
        and os.path.isfile(_live_path)
        and os.path.getsize(_live_path) > 0
    ):
        logger.info(
            "All %d sources returned 304; live blocklist %s exists; skipping render",
            len(args.sources),
            _live_path,
        )
        print(
            f"\n--- rpz-zone-factory summary ---\n"
            f"All {len(args.sources)} sources unchanged (304); no rendering needed",
            file=sys.stderr,
        )
        return EXIT_NO_CHANGES

    # Filter (cross-source dedup)
    filtered = filter_entries(all_entries)
    logger.info("After filtering: %d entries", len(filtered))

    output_text = pihole.render(filtered)

    # Write output
    if args.output_file:
        with open(args.output_file, "w", encoding="utf-8") as f:
            f.write(output_text)
        logger.info("Output written to %s", args.output_file)
    else:
        sys.stdout.write(output_text)

    # Summary to stderr
    print(f"\n--- rpz-zone-factory summary ---", file=sys.stderr)
    print(f"Sources fetched: {len(args.sources)}", file=sys.stderr)
    if not_modified_sources:
        print(f"Not modified (304): {', '.join(not_modified_sources)}", file=sys.stderr)
    print(f"Total raw entries: {len(all_entries)}", file=sys.stderr)
    print(f"After filtering: {len(filtered)}", file=sys.stderr)
    if errors:
        print(f"Source errors ({len(errors)}):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
    print(f"Output format: {args.output}", file=sys.stderr)

    return 0


def _run_per_source(
    args: argparse.Namespace,
    all_entries: list[ThreatEntry],
    errors: list[str],
    logger: logging.Logger,
    not_modified_sources: list[str] | None = None,
    errored_sources: set[str] | None = None,
) -> int:
    """Per-source mode: group entries by source, filter each independently, write separate zone files.

    Per-zone fast-path: if a source returned 304 and didn't error out,
    skip rendering that zone entirely. The shell side iterates `*.db`
    files in the staging directory, so an absent file means "no work" -
    no validation, no IXFR, no seed, no reload. --force bypasses this.
    """
    from collections import defaultdict

    if not_modified_sources is None:
        not_modified_sources = []
    if errored_sources is None:
        errored_sources = set()

    # Group entries by source key
    entries_by_source: dict[str, list[ThreatEntry]] = defaultdict(list)
    for entry in all_entries:
        source_key = _SOURCE_NAME_TO_KEY.get(entry.source.value)
        if source_key:
            entries_by_source[source_key].append(entry)

    # Determine output directory
    output_dir = args.output_file
    if not output_dir:
        print("ERROR: --per-source requires --output-file to specify an output directory", file=sys.stderr)
        return 1

    os.makedirs(output_dir, exist_ok=True)

    total_filtered = 0
    per_source_counts: dict[str, int] = {}
    skipped_sources: list[str] = []
    rendered_zone_count = 0

    for source_key in args.sources:
        zone_name = SOURCE_ZONE_NAMES.get(source_key, source_key)

        # Per-zone fast-path: 304 + no error + live zone exists → skip render.
        if (
            not args.force
            and source_key in not_modified_sources
            and source_key not in errored_sources
        ):
            _live_path = _resolve_live_zone_path(output_dir, f"{zone_name}.db")
            if os.path.isfile(_live_path) and os.path.getsize(_live_path) > 0:
                logger.info(
                    "Source %s: 304 unchanged and live %s exists - skipping render",
                    source_key,
                    _live_path,
                )
                skipped_sources.append(source_key)
                per_source_counts[source_key] = -1  # sentinel: skipped
                continue

        source_entries = entries_by_source.get(source_key, [])
        if not source_entries:
            logger.info("Source %s: no entries, skipping zone file", source_key)
            per_source_counts[source_key] = 0
            continue

        # Filter per-source (dedup within source only, no cross-source dedup)
        filtered = filter_entries(source_entries)
        per_source_counts[source_key] = len(filtered)
        total_filtered += len(filtered)

        if not filtered:
            logger.info("Source %s: all entries filtered out", source_key)
            continue
        # Compute next serial from the live zone file. In per-source mode with
        # checkzone enabled, output_dir is <real>/.tmp and the live file is at
        # <real>/<zone>.db. Otherwise output_dir IS <real> and the same-name
        # file is both the source we read and the file we're about to write
        # (so we read it BEFORE opening for write below).
        _live_path = _resolve_live_zone_path(output_dir, f"{zone_name}.db")
        _serial = compute_next_serial(_live_path)
        logger.info("Source %s: serial=%d zone=%s", source_key, _serial, zone_name)
        output_text = rpz.render(filtered, zone_name=zone_name, serial=_serial)

        zone_file = os.path.join(output_dir, f"{zone_name}.db")
        with open(zone_file, "w", encoding="utf-8") as f:
            f.write(output_text)
        logger.info("Source %s: %d entries → %s", source_key, len(filtered), zone_file)
        rendered_zone_count += 1

    # Write allowlist zone if provided.
    #
    # Allowlist fast-path: the source is a local text file, not HTTP, so
    # there's no 304 to leverage. Instead compare mtimes - if the .txt
    # hasn't been touched since the live .db was last written, the zone
    # is already in sync (allow.sh nsupdates touch the .db on every
    # change, and run-rpz.sh seeds the .db after a render). --force
    # bypasses this.
    allowlist_skipped = False
    allowlist_domains: list[str] | None = None
    if args.allowlist:
        if not os.path.isfile(args.allowlist):
            print(f"ERROR: Allowlist file not found: {args.allowlist}", file=sys.stderr)
            return 1

        _live_allowlist = _resolve_live_zone_path(output_dir, "allowlist.rpz.db")
        if (
            not args.force
            and os.path.isfile(_live_allowlist)
            and os.path.getsize(_live_allowlist) > 0
            and os.path.getmtime(args.allowlist) <= os.path.getmtime(_live_allowlist)
        ):
            logger.info(
                "Allowlist: %s unchanged since live %s - skipping render",
                args.allowlist,
                _live_allowlist,
            )
            allowlist_skipped = True
        else:
            allowlist_domains = _parse_allowlist_file(args.allowlist)
            if allowlist_domains:
                _allow_serial = compute_next_serial(_live_allowlist)
                logger.info("Allowlist: serial=%d", _allow_serial)
                allowlist_text = _render_allowlist_zone(allowlist_domains, serial=_allow_serial)
                allowlist_file = os.path.join(output_dir, "allowlist.rpz.db")
                with open(allowlist_file, "w", encoding="utf-8") as f:
                    f.write(allowlist_text)
                logger.info("Allowlist: %d domains → %s", len(allowlist_domains), allowlist_file)
                rendered_zone_count += 1
            else:
                logger.warning("Allowlist file is empty or contains no valid entries: %s", args.allowlist)

    # Summary to stderr
    print(f"\n--- rpz-zone-factory summary (per-source mode) ---", file=sys.stderr)
    print(f"Sources fetched: {len(args.sources)}", file=sys.stderr)
    if not_modified_sources:
        print(f"Not modified (304): {', '.join(not_modified_sources)}", file=sys.stderr)
    if skipped_sources:
        print(f"Skipped (304 + live exists): {', '.join(skipped_sources)}", file=sys.stderr)
    print(f"Total raw entries: {len(all_entries)}", file=sys.stderr)
    print(f"Total after filtering: {total_filtered}", file=sys.stderr)
    print(f"Per-source entry counts:", file=sys.stderr)
    for source_key in args.sources:
        count = per_source_counts.get(source_key, 0)
        zone_name = SOURCE_ZONE_NAMES.get(source_key, source_key)
        if source_key in skipped_sources:
            tag = " (skipped)"
            count_str = "-"
        elif source_key in not_modified_sources:
            tag = " (cached/304)"
            count_str = str(count)
        else:
            tag = ""
            count_str = str(count)
        print(f"  {zone_name}: {count_str}{tag}", file=sys.stderr)
    if args.allowlist:
        if allowlist_skipped:
            print(f"  allowlist.rpz: - (skipped)", file=sys.stderr)
        else:
            _al_count = len(allowlist_domains) if allowlist_domains else 0
            print(f"  allowlist.rpz: {_al_count}", file=sys.stderr)
    if errors:
        print(f"Source errors ({len(errors)}):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
    print(f"Output directory: {args.output_file}", file=sys.stderr)

    # If nothing was rendered at all (every source skipped + allowlist
    # skipped or absent), signal EXIT_NO_CHANGES so the shell skips its
    # entire post-processing pipeline. If even one zone was rendered, we
    # return 0 and let the shell process whatever .db files exist.
    if rendered_zone_count == 0 and (skipped_sources or allowlist_skipped):
        logger.info(
            "All %d sources unchanged; no zones rendered - exiting with code %d",
            len(skipped_sources) + (1 if allowlist_skipped else 0),
            EXIT_NO_CHANGES,
        )
        return EXIT_NO_CHANGES

    return 0


if __name__ == "__main__":
    sys.exit(main())
