"""Local-only raw-request client used after compromising the Web process.

There is intentionally no HTTP route for this module. It demonstrates the
remember-cookie compromise to raw-request pivot while retaining the Web role
boundary.
"""

from __future__ import annotations

import argparse

from flask import Flask

from .config import Config
from .db import submit_raw_request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--service", default="echo")
    parser.add_argument("--duration", type=int, default=420)
    parser.add_argument("--options", required=True)
    args = parser.parse_args()

    app = Flask(__name__)
    app.config.from_object(Config)
    with app.app_context():
        print(
            submit_raw_request(
                args.username,
                args.target,
                args.service,
                args.duration,
                args.options,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
