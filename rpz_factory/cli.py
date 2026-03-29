"""CLI entrypoint for rpz-zone-factory."""

from __future__ import annotations

import argparse
import logging
import sys

from rpz_factory.filters import filter_entries
from rpz_factory.models import FetchResult, ThreatEntry
from rpz_factory.parsers import abusech, cisa, spamhaus
from rpz_factory.renderers import pihole, rpz


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rpz-zone-factory",
        description="Fetch threat intel and generate RPZ zone files or Pi-hole blocklists.",
    )
    parser.add_argument(
        "--output",
        choices=["rpz", "pihole"],
        default="rpz",
        help="Output format (default: rpz)",
    )
    parser.add_argument(
        "--zone-name",
        default="rpz.local",
        help="RPZ zone name (default: rpz.local)",
    )
    parser.add_argument(
        "--output-file",
        default=None,
        help="Write output to file (default: stdout)",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        default=["urlhaus", "cisa", "drop", "edrop", "dbl"],
        choices=["urlhaus", "cisa", "drop", "edrop", "dbl"],
        help="Sources to fetch (default: all)",
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
    "edrop": spamhaus.fetch_edrop,
    "dbl": spamhaus.fetch_dbl,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    logger = logging.getLogger("rpz_factory")

    # Fetch from all requested sources
    all_entries: list[ThreatEntry] = []
    errors: list[str] = []

    for source_key in args.sources:
        fetcher = SOURCE_FETCHERS[source_key]
        logger.info("Fetching source: %s", source_key)
        try:
            result: FetchResult = fetcher()
            if result.error:
                errors.append(f"{source_key}: {result.error}")
                logger.warning("Source %s had error: %s", source_key, result.error)
            all_entries.extend(result.entries)
            logger.info(
                "Source %s: %d entries collected", source_key, len(result.entries)
            )
        except Exception as exc:
            errors.append(f"{source_key}: {exc}")
            logger.error("Source %s failed: %s", source_key, exc)

    if not all_entries:
        logger.error("No entries collected from any source")
        print("ERROR: No entries collected. Check network and sources.", file=sys.stderr)
        if errors:
            for e in errors:
                print(f"  - {e}", file=sys.stderr)
        return 1

    # Filter
    filtered = filter_entries(all_entries)
    logger.info("After filtering: %d entries", len(filtered))

    # Render
    if args.output == "rpz":
        output_text = rpz.render(filtered, zone_name=args.zone_name)
    else:
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
    print(f"Total raw entries: {len(all_entries)}", file=sys.stderr)
    print(f"After filtering: {len(filtered)}", file=sys.stderr)
    if errors:
        print(f"Source errors ({len(errors)}):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
    print(f"Output format: {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
