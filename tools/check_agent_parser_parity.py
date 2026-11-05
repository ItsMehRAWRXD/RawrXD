#!/usr/bin/env python3
"""Fail closed when the portable model reply parser drifts from production.

This is an interim guard until the parser is moved into one shared C++ unit.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
PROD = ROOT / "~dev/src/rawr_agent.cpp"
PORTABLE = ROOT / "~dev/src/rawr_agent_parse_only.cpp"
BEGIN = "struct ModelReply {"
END = "// ---------------------------------------------------------------------------\n// Chat assembly"


def production_fragment(source: str) -> str:
    start = source.find(BEGIN)
    end = source.find(END, start)
    if start < 0 or end < 0:
        raise ValueError("production parser boundary missing")
    return source[start:end].rstrip()


def portable_fragment(source: str) -> str:
    start = source.find(BEGIN)
    end = source.find("\n} // namespace", start)
    if start < 0 or end < 0:
        raise ValueError("portable parser boundary missing")
    return source[start:end].rstrip()


def main() -> int:
    try:
        expected = production_fragment(PROD.read_text(encoding="utf-8"))
        actual = portable_fragment(PORTABLE.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"PARSER_PARITY=FAIL: {exc}", file=sys.stderr)
        return 1
    if expected != actual:
        print("PARSER_PARITY=FAIL: production and portable copies differ", file=sys.stderr)
        return 1
    print("PARSER_PARITY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
