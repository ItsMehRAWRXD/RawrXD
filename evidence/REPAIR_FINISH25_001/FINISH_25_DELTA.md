# FINISH_25 delta — REPAIR_FINISH25_001

ASOF_UTC=2026-11-09T00:14:00Z
REPAIR_CANDIDATE_SHA=049F10683675D680AEDDB02543BFDEB03AC7F7E2A2372F82279F50271A25662E

| Metric | Baseline POST_E59D | Prior repair 4D35764A… | This candidate 049F1068… |
|--------|--------------------|-------------------------|---------------------------|
| FINISH_25_PASS | **19** | **19** | **19** (no new gate PASS) |
| FINISH_25_REMAINING | 6 | 6 | 6 |
| T07 | FAIL | FAIL (binary REJECTED, unicode FAIL) | FAIL (binary REJECTED, unicode FAIL) |
| T08 | FAIL stuck@1 | FAIL stuck@1 | FAIL stuck@1 |
| T17 | PASS | PASS | PASS (reconfirmed) |
| T10 | PASS | PASS | PASS (reconfirmed) |
| PROMOTE | 0 | 0 | 0 |

Credit rule: Finish-25 only for proven new PASSes. None this turn.
