# G17 (agentic_tool_integrity) — candidate evidence (NOT a certification)

Gate ledger: `G17_agentic_tool_integrity = OPEN`. This document maps the deterministic
tool-integrity evidence produced this session to G17's intent. It does **not** change the gate
status: `CERTIFIED=0  RELEASE=HELD  PROMOTE=0`. A human certifier must review and promote.

## What G17 needs (tool integrity)
Evidence that the agent's tool calls are parsed correctly, dispatched to real tools, capability-
gated, and that completion is only accepted on independently verified work (not model claims).

## Candidate evidence (all deterministic, model-free, committed)
| Property | Test | Result |
|----------|------|--------|
| Correct channel per provider (no wasted/failed native calls) | `rawr_agent --self-test-channel` | 9/9 |
| Robust tool-call extraction (prose/reasoning skipped) | `--self-test-parse` | 7/7 |
| Edit convergence (no infinite old-not-found loop) | `--self-test-edit` | 5/5 |
| No 20 s GUI-run waste | `--self-test-guirun` | 5/5 |
| Real build → short-circuit → functional gate (BUILD_PASS⇒E2E_PASS) | `--self-test-pipeline` | PASS |
| Production controller: dispatch + capability gate + no-progress + completion + staleness | `agent_controller_selftest` | 8/8 |
| Live: gpt-oss native full lifecycle, functional=1 | campaign | PASS |

## What this does NOT establish
- Model-compliance reliability (separate, model-bound; ~25% within budget).
- Swarm (G18), endurance (G19), release provenance (G20) — untouched.
- Certification — requires the full build/hardware environment + certifier authority.

## Recommendation to certifier
The tool-integrity MECHANISMS are implemented and deterministically verified. G17 may be
advanced from OPEN toward PARTIAL/VERIFIED for the mechanism layer, pending the certifier's
review and the model-compliance reliability distribution. Do not mark G17 PASS on this alone.