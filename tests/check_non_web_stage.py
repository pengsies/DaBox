#!/usr/bin/env python3
"""Compatibility entrypoint; the shared stage now includes Flask Web."""

from check_integrated_stage import main


if __name__ == "__main__":
    raise SystemExit(main())

