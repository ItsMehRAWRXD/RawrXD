# AGENT-TOOL-SCHEMA-002 — LOCK

**Status:** `PASS`  
**Frozen:** 2026-08-29  
**Mode:** `--tool-schema-cert` (model-independent lanes A/R/B)

## Lanes

| Lane | Meaning | Result |
|------|---------|--------|
| A | `RAWRXD_TOOL_ARGS_STRICT=1` — bare keys reject, `dispatched=false` | PASS |
| R | Bare-key repair → SCHEMA_VALID + dispatched | PASS |
| B | Already-strict JSON accept + dispatched | PASS |

```text
AGENT-TOOL-SCHEMA-002=PASS
LANE_A_MALFORMED_REJECT=PASS
LANE_R_BAREKEY_REPAIR=PASS
LANE_B_VALID_ACCEPT=PASS
```

Hard invariant: `SCHEMA_VALID=false ⇒ TOOL_DISPATCHED=false` (Lane A).  
Action path: TinyLlama bare-key dialect clears via logged `[TOOL_SCHEMA] REPAIR` (Lane R).

## Artifacts

- `AGENT_TOOL_SCHEMA_002_DIRECT.txt`
- `AGENT-TOOL-SCHEMA-002.lock.json`
- Regenerator: `RawrXD-Agentic.exe --tool-schema-cert --schema-cert-out …`
