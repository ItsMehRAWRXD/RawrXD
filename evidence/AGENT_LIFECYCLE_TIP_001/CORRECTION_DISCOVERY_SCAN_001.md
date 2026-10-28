# CORRECTION — Discovery scan ≠ lifecycle failure

```
ASOF_UTC=2026-10-28T11:25:00Z
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
NO_INVENT_PASS=1
TIP_SHA=6832F439100C71AE7923A7736F71784039B7F6A9DE53C895E56E9C7932A9F8B2
TIP_EXE=build_win32ide_link001\bin\RawrXD-Win32IDE.exe
REBUILD_REQUIRED=0
```

## Correction

A background recursive executable discovery scan was intentionally stopped while hung. Its process exit `-1` is **ABORTED discovery history only**.

```
DISCOVERY_SCAN_ABORTED ≠ AGENT_LIFECYCLE_FAILED
```

## Handling

- Exclude that scan exit from lifecycle pass/fail calculations.
- Do not attribute exit `-1` to `AGENT_LIFECYCLE_TIP_001` product disposition.
- Preserve existing `LAW.txt` / `RECEIPT.md` / `SUMMARY.txt` / `logs/STEPS.jsonl` without rewrite.
- This correction alone neither promotes nor invalidates the tip.

## Standing seal

`AGENT_LIFECYCLE_TIP_001` remains as previously sealed (including honest `agent_run_loop=NOT_RUN`). Next G02 work stays `AGENT_RUN_LOOP_TIP_001` exposure — unrelated to this scan.
