# AGENT-E2E-001 — LOCK

**Status:** `AGENT-E2E-001=CANDIDATE_PASS`  
**Authority:** `AGENT-E2E-001_AUTHORITY=NOT_CERTIFIED`  
**Frozen:** 2026-08-29  
**Evidence:** FROZEN

## Verdict

Win32IDE has an agentic IDE execution spine at **candidate-pass** level:

```
prompt → inspect project → identify compile failure → modify source
→ rebuild → execute repaired program → observe correct stdout
```

## Binary

| Field | Value |
|-------|-------|
| `WIN32IDE_EXE` | `F:\~dev\rawrxd\build-win32ide-fresh\bin\RawrXD-Win32IDE.exe` |
| `WIN32IDE_EXE_SHA256` | `377A6DE7FA3A5FB2F1EC69C760578956F7C7F781B26581979B5A808AEC9F41A4` |

## Gate results

| Gate | Result |
|------|--------|
| `AUTOFIX_COMPILE_REPAIR` | PASS |
| `AUTOFIX_REBUILD` | PASS |
| `AUTOFIX_EXECUTION` | PASS |
| `AUTOFIX_EXPECTED_STDOUT` | PASS |
| `EXPECTED_STDOUT` | `hello from e2e_fix` |

## Fixture

- Project: `F:\~dev\rawrxd\build-win32ide-fresh\phase2_e2e_fixture`
- Failure: intentional `UNDEFINED_SYMBOL` / `rawrxd_demo_break_function` (C2065)
- Agent path: `--autofix` → `QuantumOrchestrator::executeAutoFix`
- Model session path (GUI): `tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`

## Telemetry (frozen copy)

```
{"attemptCount":1,"totalDiagnosticsGenerated":1,"totalDiagnosticsHandled":"1","totalFixesStaged":"1","finalStatus":"success","durationMs":18663}
```

## Observed stdout

```
hello from e2e_fix
```

## Evidence root

`F:\~dev\rawrxd\build-win32ide-fresh\phase2_evidence\`

- `e2e_loop_result.json`
- `healing_telemetry.json`
- `run.out`
- `E2E_AGENT_LOOP.md`
- `AGENT-E2E-001.lock.md` (this file)
- `AGENT-E2E-001.lock.json`

## Explicit non-claims (NOT_CERTIFIED)

- Repair is **not** proven GGUF-model-directed (deterministic demo-break prepass / orchestrator path may dominate)
- `RAWRXD_ALLOW_AGENTIC_STUB_FALLBACK` dependency not closed
- Lifecycle / heap teardown debt open
- MLA → external parity → performance certification open
- Single-fixture only — suite gate is **AGENT-E2E-002**

## Next gate (recommended)

**AGENT-E2E-002**: 5–10 fixtures (compile, linker, failing unit test, multi-file, missing include/symbol, second-iteration repair) from plain-English prompts with local GGUF.
