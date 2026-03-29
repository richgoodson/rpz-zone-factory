#!/usr/bin/env python3
"""Thin entrypoint for rpz-zone-factory."""

import sys

from rpz_factory.cli import main

if __name__ == "__main__":
    sys.exit(main())
