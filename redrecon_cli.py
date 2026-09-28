#!/usr/bin/env python3
"""
REDRECON-X — Automated Web Reconnaissance & Attack-Surface Intelligence Framework
Command-Line Runner
"""
import sys

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from redrecon.cli.main import main

if __name__ == "__main__":
    main()
