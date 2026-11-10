# PROD_AUDIT_BATCH3_001 — Gates 31–45 disposition

ASOF=2026-11-03
SOURCE=agent Batch3 agent tool path
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
SOURCE_CHANGES=0
REBUILD=0

## Controlling finding

```text
CLI_TOOL_AUTHORITY=PARTIAL_VERIFIED
IDE_LINKS_PERMISSION_GATE=0
IDE_EDIT_BUILD_TEST_E2E=NOT_RUN
NATIVE_AGENT_TOOL_REGISTRY=0
BATCH3_EXIT=FAIL_CLOSED
```

Native IDE links `AgenticLoopBridge` + legacy `AgenticBridge` but does **not** link `rawrxd_agentic_backend` (`PermissionGate` / `SelfRepairLoop`). CLI component wins do not close IDE Batch-3 exit.

## Critical blockers

1. Authority split (CLI owns Tool Authority; IDE does not).
2. No certified IDE edit→build→test continuous run.
3. Legacy bridge: real PS spawn, but static tool list + Ask loop ≠ tool authority.
4. GUI mutations default read-only (`RAWRXD_GUI_APPROVE_MUTATIONS=YES` opt-in).
5. Gate 45: dual-GPU placement ≠ dual independent agent contexts.

## Batch exit (still unmet)

Native `RawrXD-Win32IDE-Native` must prove: task → MOTD/workspace → strict model tool calls → approved edits → controlled build fail → repair → tests green → cancel/idle clean.

## Law

`CLI_SMOKE != IDE_E2E` · `SOURCE_WIRED != RUNTIME_REACHED` · `NOT_RUN != PASS`
