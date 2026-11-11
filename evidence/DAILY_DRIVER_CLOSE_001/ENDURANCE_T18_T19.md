# T18/T19 — DAILY_DRIVER_CLOSE_001

ASOF_UTC=2026-11-09T07:34:11Z

```
CONTROLLING_SHA=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
TIP_EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_t05_fix\RawrXD-Win32IDE-Native.exe
T18=PASS
T19=PASS
CYCLES=12/12
SURVIVED=1
FORCE_KILL=0
PRIVATE_BYTES_START=8638464
PRIVATE_BYTES_END=16850944
PRIVATE_BYTES_DELTA=8212480
GDI_START=70
GDI_END=127
SHA_MATCH=1
PROMOTE=0
CERTIFIED=0
NOT_RUN!=PASS
```

## Method

PHASE4_5 full 100-cycle soak was **not** re-run against tip (would risk transferring 3B72-era seals / blocked cancel disposition). Instead: tip-adapted **bounded** endurance+memory smoke.

Harness: `harness_t18_t19_tip_bounded.ps1`

Per cycle: File→Open dialog → cancel → idle Stop click (id 1210) → File→New. Process must survive all cycles; memory/GDI sampled start/end.

| Gate | Result | Notes |
|------|--------|-------|
| T18 | **PASS** | 12/12 cancel/open cycles; process survived; tip SHA unchanged |
| T19 | **PASS** | start+end samples; Δpriv≈8.2MB; ΔGDI=57; under fail thresholds |

Evidence:

- `logs\t18_t19_result_20261109-023344.json`
- `logs\t18_t19_runlog_20261109-023344.txt`
- `logs\t18_t19_memory_20261109-023344.csv`

```
3B72_SEALS_TRANSFERRED=0
PHASE4_5_100_CYCLE=NOT_CLAIMED
BOUNDED_N12=PASS
```
