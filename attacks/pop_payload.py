#!/usr/bin/env python3
"""Compatibility import for the renamed Flask pickle payload helper."""

from pickle_payload import main, payload, random_result_name, validate_result_name

__all__ = ["payload", "random_result_name", "validate_result_name"]


if __name__ == "__main__":
    raise SystemExit(main())
