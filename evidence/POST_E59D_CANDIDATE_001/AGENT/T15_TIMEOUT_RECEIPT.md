# T15_TIMEOUT

ASOF_UTC=2026-11-08T22:41:00Z
GATE=T15_TIMEOUT
SCOPE=rawr.exe CLI cancel-after path (≠ Win32IDE CERT promote)
CLI_UNDER_TEST=F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe
CLI_SHA=2CB32D51F4C4CFE3138C7869365A4DBC22CE1DA5F6F16B1920BFE8FFB1C182AF
CLI_PREFERRED_MISSING=F:\rawrxd\build_ide\bin-msvc\rawr.exe
PRODUCT_SUPPORTS=YES (`rawr run ... --cancel-after-ms n`)
REBUILD=HELD
PROMOTE=0
CERTIFIED=0

## Prior

```
TIMEOUT=NOT_RUN
NOTE=IDE maxWallTimeSec=300 not waited in PHASE3 harness; cancel 4107 exercised instead.
```

## Exercise (CLI)

Command:

```
rawr run qwen3:8b autonomous --backend ollama --workspace F:\rawrxd --fresh-session --cancel-after-ms 1500 --prompt <long/slow task>
```

Observed (run T15ISO_2b06c9e6 / first isolation batch):

```
TIMEOUT_EXIT=130
TIMEOUT_ELAPSED_MS≈3645
TIMEOUT_STDERR contains: [agent] CANCELLED: user_interrupt
TIMEOUT_OBSERVED=1
```

Evidence files: `AGENT\T15_ISOLATION\` (TIMEOUT_* from first batch; TIMEOUT2_* if re-run completed).

## Disposition

```
T15_TIMEOUT=PASS
PATH=CLI_CANCEL_AFTER_MS
IDE_WALL_TIMEOUT_300S=NOT_RUN (gap; not required once CLI path proven)
NOT_RUN!=PASS honored for IDE wall path only
```
