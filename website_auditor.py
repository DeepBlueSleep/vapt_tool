#!/usr/bin/env python
"""Backward-compatible entrypoint for the asynchronous scanner package."""

from __future__ import annotations

import sys

from scanner.cli import main

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
