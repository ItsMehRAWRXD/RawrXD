# TIP005_HWND_REPAIR

ASOF_UTC=2026-11-09T13:16:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0

```
ACTIVE_REPAIR=TIP005_HWND
TIP_SHA=30B9BA7899FB8C7D4A0AAE3B1B81883B5C7DBA2606CFA28396A3517273BFC393
TIP_PATH=package\tip_hwnd_repair_001 (also tip_final_007)
TIP006_NOT_OVERWRITTEN_BY_THIS_WORKER=1
CC79_UNREPLACED=1
A4F_UNTOUCHED=1
OUTPUT_HWND=PASS
PROBLEMS_HWND=PASS
CLICK_TO_LINE=POSTED_NM_DBLCLK_LINE1
DISPATCH_ID_WIRE=SOURCE_STRINGS_PRESENT
DISPATCH_ID_CORRELATION=RUNTIME_AND_TRANSCRIPT_HIT
EXACTLY_ONCE_DELIVERY=NOT_VERIFIED
CHAT_TRANSCRIPT_17=PRESERVED_NO_FURTHER_ACTION
```

## Measured (tip_hwnd_repair_001 / tip_final_007)

| Gate | Result | Evidence |
|------|--------|----------|
| OUTPUT id1604 | **PASS** LEN=990 | real `error C2065` / `C2660` cl lines; CHAT_CONTAMINATED=0 |
| PROBLEMS id1312 | **PASS** peak=3 | fixture launch=1; MSVC hits=3 |
| CLICK_TO_LINE | POSTED + LINE1 | WM_LBUTTONDBLCLK (not cross-proc WM_NOTIFY) |
| dispatch_id | RUNTIME_AND_TRANSCRIPT_HIT | 3 SEND_ATTEMPT (1 ARMED / 2 BUSY); transcript `[dispatch_id=1] corr-probe-1`; EXACTLY_ONCE=NOT_VERIFIED |
| tip_final_006 | not written by this worker | seal 5A71CA26… preserved; external drift 69FE3D92… is NOT the seal |

## Product fixes landed

1. Build Output control IDs **1604–1611** + `SetWindowLongPtr(GWLP_ID)`.
2. `appendText` → `EM_REPLACESEL` so Build channel accumulates ConPTY/cl text.
3. `addProblemPublic` + ANSI strip ingest for Problems from ConPTY.
4. Click-to-line: select via in-HWND `WM_LBUTTONDBLCLK`; Core/lifecycle fallback idx=0.
5. Per-message dispatch_id correlation measured on this SHA (runtime journal + ARMED transcript tag). Exactly-once remains NOT_VERIFIED.
