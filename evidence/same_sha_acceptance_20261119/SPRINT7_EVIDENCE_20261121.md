# Sprint 7 — backend acceptance evidence (2026-11-21)

All probes use the corrected `SendMessageTimeoutW` pattern (transport success
separate from the out-param result). Build: `RawrXD-Win32IDE-Native` +
`RawrXD-CLI-V2` (Release).

## 7A — Portable GUI restoration  => PASS
`gui_backend_restore_probe.ps1` (persists each value via the shared resolver,
launches the IDE, reads control 1226):
```
backend=deep2  persisted=deep2  COUNT=3 CURSEL=0 expect=0 => PASS
backend=strata persisted=strata COUNT=3 CURSEL=1 expect=1 => PASS
backend=ollama persisted=ollama COUNT=3 CURSEL=2 expect=2 => PASS
GUI_RESTORE_ALL=PASS
```

## 7B — Correct status semantics  => PASS
`rawr backend status` with persisted=deep2/strata/ollama no longer reports the
configured Ollama service as the active backend. For Strata:
```
selected    : strata
route       : strata
routable    : no
active      : none
endpoint    : none
reachable   : NO
route_error : STRATA_NOT_ROUTABLE
```
(JSON now also carries `routable` and `route_error`.)

## 7C — Refresh stability  => PASS
`gui_backend_refresh_probe.ps1` (read, CBN_SELCHANGE + CB_SETCURSEL same index,
re-read):
```
BEFORE COUNT=3 CURSEL=1 BLANK=0
AFTER  COUNT=3 CURSEL=1 BLANK=0
REFRESH_STABLE=PASS
```

## 7D — Strata fail-closed routing  => PASS
Request level (`rawr ask "2+2"` with persisted=strata):
```
exit=1
ERROR: STRATA_NOT_ROUTABLE: expert residency is not activated on this path;
use --backend=deep2 or --backend=ollama
```
The `cmdAsk`/`cmdRun` handlers return `EXIT_FAIL` for `strata` **before** any
model resolution or `resolvePreferredEndpoint` (the only place Ollama is
probed), so no Ollama request is issued and Deep2 is not substituted.

## 7E — Clean-source build  => PENDING
Active-tree builds of `RawrXD-Win32IDE-Native` and `RawrXD-CLI-V2` PASS. An
isolated worktree build at the recorded commit is required to fully close this
gate without disturbing the concurrent Deep2/REAP working tree.

## Updated release ledger
```
SPRINTS_1_TO_6=IMPLEMENTATION_CLOSED
SPRINT_7=PARTIAL (7A/7B/7C/7D PASS; 7E/7F pending)

BACKEND_PREFERENCE_COMMIT=5b2656a532
BACKEND_PREFERENCE_CONSOLIDATION=PASS
BACKEND_STATE_PORTABILITY=PASS
BACKEND_ATOMIC_REPLACE=PASS
BACKEND_CONCURRENT_WRITES=PASS
BACKEND_LEGACY_MIGRATION=PASS
BACKEND_GUI_RESTORE=PASS
BACKEND_STATUS_SEMANTICS=PASS
BACKEND_REFRESH_STABILITY=PASS
STRATA_FAIL_CLOSED=PASS

GUI_ACCEPTANCE=16/17 (clean-tree IDE link remaining)
GLOBAL_PROBE_HARDENING=PASS
MODEL_SELECTOR_1206=PASS
BACKEND_SELECTOR_1226=PASS
CLEAN_TREE_IDE_LINK=PENDING

STRATA_DENSE_SESSION=PASS
STRATA_MOE_SESSION=PASS
STRATA_EXPERT_LEDGER=PASS
STRATA_PHYSICAL_WEIGHT_CACHE=OPEN_DEFECT
STRATA_IDE_ROUTING=PENDING (guard verified; native route owned by Strata agent)

PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```