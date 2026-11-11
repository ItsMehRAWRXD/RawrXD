# Immutable slim daily-driver baseline

ASOF_UTC=2026-11-09T07:46:00Z
IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

```
BASELINE_ID=SLIM_DAILY_DRIVER_A4F083DF
FROZEN_PACKAGE_SHA=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
SIZE=2601472
EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe
PROFILE=SLIM_WIN32IDE_NATIVE
SLIM_DAILY_DRIVER_ACCEPTANCE=PASS
FULL_FEATURE_DAILY_DRIVER=FAIL
EXT=OUT_OF_SCOPE
FINISH_25_HISTORICAL=19/25
FINISH_25_NE_REWRITTEN=1
```

## Scope closed (slim only)

| Gate | Status |
|------|--------|
| T05 cancel | PASS |
| T07 / T08 / T10 / T17 | PASS (same-SHA) |
| T16 | PASS |
| T18 / T19 | PASS (bounded N=12) |
| EXT / VSIX | OUT_OF_SCOPE — NOT_RUN ≠ PASS |

## Verified rollback artifacts (SHA-checked 2026-11-09)

| File | SHA-256 | Size |
|------|---------|------|
| `RawrXD-Win32IDE-Native.exe` (frozen) | `A4F083DF…` | 2601472 |
| `…exe.18FA04F9.bak` | `18FA04F9CAA2BC762279DE7C1AC30DEEBD83D357BCD0133ABFEC2F043E531E68` | 2509824 |
| `…exe.9C910599.bak` | `CE4F471DD31E835B0EFFFC0E757C35F07FC81B86A5269654271E7121AE7C1187` | 2594304 |

**Rollback law:** restore only after re-hashing the bak. The `9C910599` **filename** does **not** equal content SHA `9C910599…` (content is `CE4F471D…`). Prefer restoring from this table’s measured SHA, not the filename label alone. Prior progression tip `9C910599…` (SIZE=2592256) remains a separate historical seal; do not assume bak ≡ that tip without re-measure.

## Immutability law

```
Do not overwrite package\RawrXD-Win32IDE-Native.exe in place for tip experiments.
Stage new candidates under package\tip_*\ or a new baseline ID.
SLIM_ACCEPTANCE ≠ FULL_FEATURE ≠ CERTIFIED ≠ PROMOTE
Judgment readiness % ≠ measured gate score
BASELINE_PRESERVED=1
```

Authority: `GATE_BOARD.md` · `package\DAILY_DRIVER_FREEZE.md` · `SLIM_DAILY_DRIVER_EXT_POLICY.md`
