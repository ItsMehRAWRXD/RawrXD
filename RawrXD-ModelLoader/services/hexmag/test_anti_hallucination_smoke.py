#!/usr/bin/env python3
"""HEXMAG_ANTI_HALLUCINATION + ASK_USER + SELF_BUILD smoke (offline)."""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.arena import HexMagKernel, Resolution  # noqa: E402


async def main() -> int:
    k = HexMagKernel()
    out: dict = {"HEXMAG_ANTI_HALLUCINATION_INVARIANT": True}

    # 1) Arithmetic — must PROVEN via reverse, not guess
    r1 = await k.ask_with_certs("What is 17% of 843?")
    out["arith"] = {
        "resolution": r1["resolution"],
        "answer": r1["answer"],
        "self_build_PASS": r1["self_build_cert"]["PASS"],
        "finalize_ok": r1["meta"].get("finalize_allowed"),
    }

    # 2) Open-world — ASK_USER, never invent a winner
    r2 = await k.ask("Who won an election that happened yesterday?")
    ans2 = (r2.get("answer") or "").lower()
    invented = any(x in ans2 for x in ("won the election", "person a", "i think", "probably"))
    out["open_world"] = {
        "resolution": r2["meta"].get("resolution"),
        "suspended": r2["meta"].get("suspended"),
        "invented": invented,
        "ASK_USER_PASS": r2["meta"].get("resolution") == "NeedUserInput" and not invented,
    }

    # 3) SE without diagnostics — must not finalize unsupported hypothesis as fact
    r3 = await k.ask("Fix the bug in add() so add(2,3) returns 5")
    out["se_no_evidence"] = {
        "resolution": r3["meta"].get("resolution"),
        "finalize_allowed": r3["meta"].get("finalize_allowed"),
        "NO_FABRICATE_PASS": r3["meta"].get("resolution") == "NeedUserInput"
        or r3["meta"].get("finalize_allowed") is False,
    }

    out["PASS"] = (
        out["arith"]["self_build_PASS"]
        and out["open_world"]["ASK_USER_PASS"]
        and out["se_no_evidence"]["NO_FABRICATE_PASS"]
    )

    evidence = Path(r"g:\rawrxd\docs") / ".." / "RawrXD-ModelLoader" / "services" / "hexmag" / "evidence"
    # Prefer repo-relative evidence under services/hexmag
    ev = ROOT / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "HEXMAG_ANTI_HALLUCINATION_001.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8"
    )
    print(json.dumps(out, indent=2))
    return 0 if out["PASS"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
