# AGENT-TOOL-SCHEMA-002 — LOCK

**Status:** `PASS` (architectural lanes A+B; model-independent)
**Frozen:** 2026-08-29T18:03:28Z (direct cert)

## Hard invariants

```text
SCHEMA_VALID == false  =>  TOOL_DISPATCHED == false
INVALID_ARGS_REJECTED  = true
VALIDATION_ERROR_TO_MODEL = true (structured error=schema_validation)
No silent bare-key REPAIR
```

## Lanes

| Lane | Result |
| --- | --- |
| A — malformed historical args | **PASS** (`dispatched=0`, `error=schema_validation`) |
| B — strict JSON accept/dispatch | **PASS** |
| `VALID_SCHEMA_LANE` | **PASS** |
| `AGENT-TOOL-SCHEMA-002` | **PASS** |

Historical Lane A inputs (direct, no model):

```text
TOOL_CALL: replace_in_file {path:main.c, search: "DOES_NOT_EXIST", replace: "42"}
TOOL_CALL: run_command {command: "cmake --build build"}
```

## Step-2 render plumbing (related, not the schema gate)

Prior TinyLlama smoke: after valid `read_file`, model echoed `TOOL_RESULT:` — taught by role-heal prefix.
Dump: `RAWRXD_AGENT_STEP2_RENDERED_PROMPT.txt`

```text
STEP2_CONTAINS_TOOL_RESULT_LABEL = 0
STEP2_CONTAINS_OBSERVATION       = 1
STEP2_ENDS_WITH_ASSISTANT_PROMPT = 1
```

Tool→user heal now uses `Observation from \`tool\` ...` (no `TOOL_RESULT:` echo teacher).
**Next agent defect (separate):** NEXT TOOL DECISION after observation — not re-judged here.

## How to re-run

```text
RawrXD-Agentic.exe --tool-schema-cert --workspace <fixture_copy> --model <gguf> --schema-cert-out evidence/AGENT_TOOL_SCHEMA_002
```

## Artifacts

- `AGENT_TOOL_SCHEMA_002_DIRECT.txt`
- `AGENT-TOOL-SCHEMA-002.lock.json`
- `RAWRXD_AGENT_STEP2_RENDERED_PROMPT.txt`
- prior smoke: `evidence/AGENT_TOOL_SCHEMA_002/smoke/`
