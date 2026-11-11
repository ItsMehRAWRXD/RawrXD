# B20_EXT_CLEANUP_RECEIPT — Extension clean quit on reconciled candidate

```text
ASOF_UTC=2026-11-09T13:18:30Z
GATE_ID=B20
REGISTER_TITLE=Extension cleanup FAIL (FORCE_KILL=1) [historical on 47451F24]
MEASURED_SHA256=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
NO_INHERIT_47451=1
HARNESS=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\ext_smoke_oneshot.ps1
FIXTURE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\ext_hello
RUNLOG=F:\rawrxd\evidence\FULL_FEATURE_EXTENSIONHOST_001\logs\ext_smoke_run_20261109-081823.txt
SUMMARY=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\ext_smoke_summary_20261109-081823.json
A4F_UNTOUCHED=1
PROMOTE=0
```

## Measured

| Field | Value |
|-------|-------|
| SMOKE_A_EXIT | **0** |
| FORCE_KILL | **0** |
| ORPHANS | **0** |
| INIT/LOAD/ACTIVATE/CMD | 1 |
| DEACTIVATE/RELOAD | 1 |
| MALFORMED_FAULT_ISOLATED | 1 |
| SMOKE_B_EXIT | 0 |
| HARNESS_EXIT | 0 |
| EXT_LOAD | PASS |
| EXT_ACTIVATE | PASS |
| EXT_UNLOAD | PASS |
| EXT_CLEANUP | **PASS** |
| EXTENSIONS | **PASS** |

```text
B20_DISPOSITION=PASS
B20_CLOSED=1
REBUILD_REQUIRED=0
SHA_UNCHANGED=27E2263E…
NOTE=Historical FORCE_KILL=1 was on absent 47451F24; this close is SHA-bound to 27E2263E only
```

No source fix / rebuild required this turn — clean `--ext-quit` already demonstrated on the reconciled image.
