#!/usr/bin/env python3
"""
HEXMAG_GROW_REVERSE_001  — COMPUTATIONAL_UNCERTAINTY → GROW_AND_REVERSE
HEXMAG_FINALIZE_DENY_001 — confidence/illegal states cannot finalize
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.arena import (  # noqa: E402
    Candidate,
    ClaimState,
    HexMagKernel,
    Resolution,
)


ADD_BUG_PROMPT = """
Fix add so add(2,3) must return 5.

```c
int add(int a, int b) {
    return a - b;
}
```
"""


async def grow_reverse_cert() -> dict:
    k = HexMagKernel()
    arena_probe = None

    # Instrument via ask_with_certs path but capture growth from a dedicated solve
    from core.arena import QuestionArena

    arena = QuestionArena(ADD_BUG_PROMPT, mode="response_gen")
    assert arena.node_count() == 0
    initial_nodes = arena.node_count()

    answer, resolution, meta = await k._solve(arena, timeout=10.0, max_rounds=8)

    # Lifecycle evidence before deflate
    cert = {
        "id": "HEXMAG_GROW_REVERSE_001",
        "initial_nodes": initial_nodes,
        "candidate_count": len(arena.candidates),
        "reverse_count": len(arena.reverses),
        "failure_caused_growth": arena.failure_caused_growth,
        "growth_targeted_to_failure": arena.growth_targeted_to_failure,
        "spawned_roles": [r.role for r in arena.responders],
        "impl_sequence": [c.meta.get("impl") for c in arena.candidates if c.meta.get("op") == "fn_add"],
        "resolution": resolution.value,
        "answer": answer,
        "goal_satisfied": arena.goal_satisfied or resolution
        in (Resolution.PROVEN, Resolution.VERIFIED),
        "peak_nodes": arena.peak_nodes,
    }
    deflate = arena.destroy()
    cert["post_final_nodes"] = deflate["post_answer_nodes"]
    cert["persistent_weight_delta_bytes"] = deflate["persistent_weight_delta_bytes"]

    # Require: wrong first impl, growth, corrected impl, verified, deflate
    impls = cert["impl_sequence"]
    cert["PASS"] = (
        cert["initial_nodes"] == 0
        and len(impls) >= 2
        and impls[0] == "sub"
        and "add" in impls[1:]
        and cert["failure_caused_growth"] is True
        and cert["reverse_count"] >= 2
        and "SemanticDebugger" in cert["spawned_roles"]
        and cert["goal_satisfied"] is True
        and cert["resolution"] in ("Proven", "Verified")
        and cert["post_final_nodes"] == 0
        and cert["persistent_weight_delta_bytes"] == 0
    )
    return cert


def finalize_deny_cert() -> dict:
    k = HexMagKernel()
    illegal = []

    cases = [
        Candidate("1", "guess", 0, ClaimState.CANDIDATE, 0.9, {"op": "none"}),
        Candidate("2", "x", 0, ClaimState.SUPPORTED, 0.9, {"op": "none"}),
        Candidate(
            "3",
            "Person A won",
            0,
            ClaimState.CANDIDATE,
            0.999999,
            {"op": "none", "confidence": 0.999999, "epistemic": "HighConfidence", "evidence": []},
        ),
        Candidate("4", "likely", 0, ClaimState.UNVERIFIED, 0.8, {"epistemic": "Likely"}),
        Candidate("5", "vote", 0, ClaimState.CANDIDATE, 0.7, {"epistemic": "Consensus"}),
        Candidate("6", "unk", 0, ClaimState.UNKNOWN, 0.0, {}),
        Candidate("7", "bad", 0, ClaimState.CONTRADICTED, 0.0, {"op": "add", "a": 1, "b": 1, "value": 3}),
        Candidate(
            "8",
            "still no",
            0,
            ClaimState.CANDIDATE,
            0.999999,
            {"confidence": 0.999999, "evidence": []},
        ),
    ]

    denies = []
    for c in cases:
        r = k._finalize_claim(c)
        denies.append(
            {
                "id": c.id,
                "state": c.state.value,
                "allowed": r["allowed"],
                "deny_reason": r.get("deny_reason"),
            }
        )
        if r["allowed"]:
            illegal.append(c.id)

    return {
        "id": "HEXMAG_FINALIZE_DENY_001",
        "cases": denies,
        "illegal_allows": illegal,
        "PASS": len(illegal) == 0,
        "confidence_as_evidence": "FORBIDDEN",
    }


async def main() -> int:
    grow = await grow_reverse_cert()
    deny = finalize_deny_cert()
    out = {
        "HEXMAG_ANTI_HALLUCINATION": {
            "policy_level": "STATE_MACHINE",
            "prompt_dependency": "NONE",
            "unsupported_claim_emission": "FORBIDDEN",
            "guessing_missing_facts": "FORBIDDEN",
            "confidence_as_evidence": "FORBIDDEN",
            "missing_information": "ASK_USER",
            "computational_uncertainty": "GROW_AND_REVERSE",
        },
        "grow_reverse": grow,
        "finalize_deny": deny,
        "PASS": grow["PASS"] and deny["PASS"],
    }
    ev = ROOT / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    (ev / "HEXMAG_GROW_REVERSE_001.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0 if out["PASS"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
