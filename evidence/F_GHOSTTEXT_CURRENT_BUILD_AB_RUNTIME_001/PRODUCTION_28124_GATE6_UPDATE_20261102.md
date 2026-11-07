# Production SHA `28124CD2…` Gate 6 update

This is an append-only update to the earlier held receipts. It does not rewrite historical verdicts.

## Exact current-build proof

The following independently recorded scopes now exist for the same production executable:

1. Native editor focus/input and explicit `qwen3:8b` selector commitment: `EXACT_HASH_28124_TRACE.md`.
2. Normal GhostText lifecycle and qwen/Ollama routing: `EXACT_HASH_28124_NORMAL_LIFECYCLE_RECEIPT_20261102.md`.
3. Deterministic A/B ordering, B rendering, late-A rejection, and normal process exit: `EXACT_HASH_28124_AB_RACE_RECEIPT_20261102_044215.md`.

All three identify:

```ini
PRODUCTION_EXE=F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe
PRODUCTION_SHA256=28124CD278C1E6457CD1CF47D6B777AC0B9FAFF6469E3BA04DDA8C76523894D8
```

## Scope verdict

```ini
PRODUCTION_QWEN3_8B_OLLAMA_ROUTE=PASS
PRODUCTION_GHOSTTEXT_REQUEST_A=PASS
PRODUCTION_GHOSTTEXT_REQUEST_B=PASS
PRODUCTION_B_RENDER_BEFORE_A=PASS
PRODUCTION_LATE_A_REJECTION=PASS
PRODUCTION_EDITOR_FOCUS_AND_INPUT=PASS_PRIOR_EXACT_HASH_SCOPE
PRODUCTION_NORMAL_SHUTDOWN=PASS
GATE6_PRODUCTION_GHOSTTEXT_SCOPE=PASS
```

## Remaining certification boundary

This closes the previously missing exact-hash A/B runtime proof for the production binary. It does not certify the separate numerical/Kimi/GPU/Phi-3 gates, Qwen3.6 full-parity gate, or overall product promotion. Those remain independently open and `PROMOTE=0` is preserved.

```ini
GATE6_PRODUCTION=PASS_SCOPE_COMPLETE
GLOBAL_CERTIFICATION=OPEN
PROMOTE=0
CERTIFIED=0
```
