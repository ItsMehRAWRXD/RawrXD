# PHASE1 T02 — Dump triad compare (070906 / 073409 / 092638)

ASOF_UTC=2026-11-03T14:46:30Z
GATE=FINISH_25_BACKLOG_PHASE1_T02
AUTH=FINISH_25_BACKLOG
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
PROMOTE=0
REBUILD=HELD
PRODUCT_DEFECT=NOT_PROVEN

Parser: `CANCEL\logs\parse_native_stack_residual.ps1`
Outputs:
- `CANCEL\logs\stack_parse_070906.txt` (prior sealed)
- `CANCEL\logs\stack_parse_073409.txt` (prior sealed)
- `CANCEL\logs\stack_parse_092638.txt` (this turn)

## Exception CONTEXT compare

| Field | 070906 (triple) | 073409 (single BM) | 092638 (BATCH1 narrow) | Match |
|-------|-----------------|--------------------|------------------------|-------|
| ExceptionCode | 0xC0000005 | 0xC0000005 | 0xC0000005 | Y |
| Write (Info0) | 1 | 1 | 1 | Y |
| RIP | comctl32+0xBD02 | comctl32+0xBD02 | comctl32+0xBD02 | Y |
| RDX | 0xFFFF | 0xFFFF | 0xFFFF | Y |
| R8 | 0 | 0 | 0 | Y |
| R9 | 0x7FFEFFFF | 0x7FFEFFFF | 0x7FFEFFFF | Y |
| RBP | 0xF000 | 0xF000 | 0xF000 | Y (anomalous) |
| Info1/RCX target | 0x154AE8E0D0 | 0x22B44CDCE0 | 0x475AC8E230 | N (VA only) |
| Exception TID | 16940 | 27444 | 8932 | N |
| ThreadCount | 16 | 15 | 16 | ~ |
| Dual comctl32 | Y same bases | Y same bases | Y same bases | Y |
| Product base | 0x7FF65A190000 | 0x7FF65A190000 | 0x7FF65A190000 | Y |

## Near-RSP class

All three: fault RIP `comctl32+0xBD02` → `comctl32+0x17C1E` → `comctl32+0x18EC8` family → user32 dispatch → product pump frames `+0x12FB9C` / `+0x33F9` / `+0x583420`.

092638 extras near mid-stack: `CoreMessaging.dll` frames; product `+0x11BB30` (not in prior two near-RSP tops).

```
SAME_PATH=YES
FAULT_SIGNATURE=PROVEN_COMCTL32_RVA_0xBD02
CONCRETE_CALLBACK=NOT_PROVEN
CRASH_ROOT_CAUSE=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
```

## Shared product RVAs (all three dumps)

```
+0x12FB9C
+0x33F9
+0x583420 (repeated)
+0x583600
+0x492FC8
+0x49B2B0
+0x49B908
```

092638-only near scan: `+0x11BB30`
070906-only near mid: `+0x1365D4`

## Result

```
T02=PASS
TRIAD_COMPARE=COMPLETE
SAME_PATH=YES
NEW_ROOT_CAUSE=0
PRODUCT_DEFECT=NOT_PROVEN
REBUILD=HELD
PROMOTE=0
```
