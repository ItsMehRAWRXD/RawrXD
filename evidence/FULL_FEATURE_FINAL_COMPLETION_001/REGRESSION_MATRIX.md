# REGRESSION_MATRIX — FULL_FEATURE_FINAL_COMPLETION_001

ASOF_UTC=2026-11-09T10:08:00Z
FINAL_CANDIDATE_SHA256=EA5D9B6979E8A60DD6899CCA23B3762CA48695234A18965534E4C1E7732442AE
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0

| Check | Prior / peer | On EA5D tip_final_004 | Disposition |
|-------|--------------|------------------------|-------------|
| A4F untouched | A4F083DF… | preserved | PASS |
| T10 freeze | PASS 9C910599 | preserved | PASS |
| EXT load/cmd | FAIL on 7582/BD529 reaffirm | **PASS** | IMPROVED |
| Chat AIM 7/7 | 6/7 CJK FAIL on 4DCB5541 | **PASS** | IMPROVED |
| Terminal full matrix | PASS D28128AE | NOT_RUN on EA5D | OPEN (other SHA) |
| Debug headless | PASS 7F8EB407 | NOT_RUN on EA5D | OPEN (other SHA) |
| Debug RelWithDebInfo tip | pending | NOT_STAGED | OPEN |
| Four-panel GUI | PARTIAL | NOT_VERIFIED | OPEN |
| Packaging RC | BD529691 stage | PARTIAL tip stage | OPEN full RC |

```
IMPROVED_EXT_CHAT != PRODUCT_PASS
PEER_TERMINAL_PASS(D28128AE) != TERMINAL_PASS(EA5D)
NO_INVENT_PASS=1
```
