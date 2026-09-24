#!/usr/bin/env python3
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    files = sorted(
        path
        for directory in ("attacks", "control", "host", "tests", "web")
        for path in (ROOT / directory).rglob("*.py")
        if "__pycache__" not in path.parts
    )
    for path in files:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    print(f"PASS: parsed {len(files)} Python source files without writing bytecode")


if __name__ == "__main__":
    main()
