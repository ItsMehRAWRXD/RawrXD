# CERT_001 receipts

One file per measured gate attempt: `Gxx-yy_<stamp>_<short>.md`  
Full evidence schema required for RESULT=PASS.  
RELATED ≠ PASS. EVIDENCE_PARTIAL ≠ PASS.

## Landed (2026-11-13 · SELF_MEASURE · freeze dde963941aa4)

| Receipt | RESULT |
|---------|--------|
| `G01-01_20261113_dde963941aa4.md` | EVIDENCE_PARTIAL |
| `G01-02_20261113_dde963941aa4.md` | EVIDENCE_PARTIAL |
| `G01-03_20261113_dde963941aa4.md` | EVIDENCE_PARTIAL (rebuild EXIT=2 @d88239) |
| `G01-04_20261113_dde963941aa4.md` | NOT_RUN (CLI fail + GUI heavy) |
| `G01-05_20261113_dde963941aa4.md` | NOT_RUN (no success rebuild pair) |
| `G01-06_20261113_dde963941aa4.md` | EVIDENCE_PARTIAL (toolchain SHA inventory) |
| `G01-07_20261113_dde963941aa4.md` | NOT_RUN (CI not dispatched) |
| `G01-08_20261113_dde963941aa4.md` | EVIDENCE_PARTIAL (stub inventory) |
| `_g01_03_build_capture_d88239.txt` | build log artifact |
| `_g01_03_build_run_d88239.bat` | exact COMMAND wrapper |

Prior: `G01-01/02/03_*_3d0928e74888.md` (superseded for matrix pointer).

PASS_COUNT=0 · PROMOTE=0 · CLEAN_MACHINE=0 · SUCCESS_EXE_SHA256=NONE
