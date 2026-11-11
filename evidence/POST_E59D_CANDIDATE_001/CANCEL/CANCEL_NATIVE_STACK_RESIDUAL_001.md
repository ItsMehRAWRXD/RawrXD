# CANCEL_NATIVE_STACK_RESIDUAL_001

ASOF_UTC=2026-11-03T12:50:00Z
GITHUB_COMMIT=70fe7cdaf7
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
CHATWINDOW_REOPEN=0
TOKEN64_REOPEN=0
GHOSTTEXT_REOPEN=0

## Controlling return

```
NATIVE_STACK=PARTIAL
STACK_METHOD=OFFLINE_MINIDUMP_EXCEPTION_CTX_PLUS_RSP_MODULE_SCAN
CDB_WINDBG=NOT_INSTALLED
PDB_SYMBOLS=NOT_PRESENT_ON_CERT_BIN
SAME_PATH=YES
PRODUCT_FRAMES_ON_FAULTING_THREAD_STACK=YES
PRODUCT_DEFECT=NOT_PROVEN
CONCRETE_CALLBACK=NOT_PROVEN
REBUILD=HELD
PROMOTE=0
```

## Dumps inspected (offline)

| Dump | Role | Exception TID | Fault |
|------|------|---------------|-------|
| `CANCEL\logs\rawrxd-20261103-073409.dmp` | single BM_CLICK Cancel | 27444 | `0xC0000005` write @ `comctl32.dll+0xBD02` |
| `CANCEL\logs\rawrxd-20261103-070906.dmp` | original triple Cancel | 16940 | `0xC0000005` write @ `comctl32.dll+0xBD02` |

CrashDumps folder: no additional usable copies located this pass.
Parser: `CANCEL\logs\parse_native_stack_residual.ps1`
Outputs: `CANCEL\logs\stack_parse_073409.txt`, `CANCEL\logs\stack_parse_070906.txt`

cdb/WinDbg: **not installed** (`Windows Kits\...\cdb.exe` absent). No `!analyze` / `.ecxr` / `kv` / `~* k`.

## Exception context (compare)

| Field | 073409 (single BM) | 070906 (original) | Match |
|-------|--------------------|-------------------|-------|
| ExceptionCode | `0xC0000005` | `0xC0000005` | Y |
| RIP | `comctl32.dll+0xBD02` | `comctl32.dll+0xBD02` | Y |
| Info[0] write | 1 | 1 | Y |
| Info[1] target | `0x22B44CDCE0` | `0x154AE8E0D0` | N (VA only) |
| RCX (== target) | `0x22B44CDCE0` | `0x154AE8E0D0` | N (VA only) |
| RDX | `0xFFFF` | `0xFFFF` | Y |
| R8 | 0 | 0 | Y |
| R9 | `0x7FFEFFFF` | `0x7FFEFFFF` | Y |
| RBP | `0xF000` | `0xF000` | Y (anomalous) |
| Dual comctl32 | Y (0x7FFC7BE70000 + 0x7FFC92430000) | Y (same bases) | Y |
| Product image base | `0x7FF65A190000` | `0x7FF65A190000` | Y |

## Near-RSP path (highest-confidence residual)

Both dumps show the same class of chain immediately above the fault:

```
comctl32.dll+0xBD02          (RIP / fault)
comctl32.dll+0x17C1E
comctl32.dll+0x18EC8
[user32.dll message-dispatch RVAs]
comctl32.dll+0x18350 (recurring)
ntdll / win32u participation
```

073409 near-RSP (excerpt):

```
[0] RIP  comctl32.dll+0xBD02
[1] RET  comctl32.dll+0x17C1E
[2] RET  comctl32.dll+0x18EC8
[3] RET  ntdll.dll+0x2F8DE
[4..]    user32.dll+0x152E6 / +0x154B9 / +0x150C2 / +0x14B6C
```

070906 near-RSP (excerpt):

```
[0] RIP  comctl32.dll+0xBD02
[1] RET  comctl32.dll+0x17C1E
[2] RET  user32.dll+0x165EA
[3] RET  comctl32.dll+0x18EC8
[4] RET  comctl32.dll+0x266B5
[5] RET  ntdll.dll+0x2F8DE
[6..]    user32 / comctl32 continuation (same family)
```

**SAME_PATH=YES** for Win32 UI / comctl32 callback class across single-BM and original Cancel dumps.

## Product frames on faulting thread stack scan

RSP module-mapped candidates include `RawrXD-Win32IDE-Native.exe` in **both** dumps.

Shared product RVAs (both dumps):

```
+0x12FB9C
+0x33F9
+0x583420 (repeated)
+0x583600
+0x492FC8
+0x49B2B0
+0x49B908
```

070906-only extra near mid-stack: `+0x1365D4`.

Counts: 073409 PRODUCT_FRAMES=13 · 070906 PRODUCT_FRAMES=14.

### Lifetime / reentrancy (what is / is not visible)

Visible:

- Fault is **user-callback-class** (`STATUS_FATAL_USER_CALLBACK_EXCEPTION` process exit already sealed; underlying AV write through RCX).
- Faulting thread stack memory present; RSP inside thread stack range.
- Dual `comctl32.dll` mappings remain.
- Product code addresses coexist on the same faulting thread stack as comctl32/user32 dispatch.

Not visible / not proven from these dumps alone:

- HWND ownership / destruction ordering
- Exact window-proc or control subclass identity
- Whether product frames are true callers vs stale stack slots (scan ≠ StackWalk64)
- Named ChatWindow/Cancel callback with source mapping (no PDB on cert bin)

## Classification (fail-closed)

| Claim | Status |
|-------|--------|
| Native exception context recovered | **PROVEN** |
| Fault module+RVA | **PROVEN** `comctl32+0xBD02` |
| Same UI path both dumps | **YES** |
| Product image on faulting thread stack | **YES** (scan) |
| Exact product callback / defective code path | **NOT_PROVEN** |
| PRODUCT_DEFECT (rebuild-authorizing) | **NOT_PROVEN** |
| Sole-harness cause | **REFUTED** (prior; unchanged) |
| CRASH_CLASSIFICATION | **MIXED** (unchanged) |

Do **not** infer app root cause solely from comctl32 fault address.
Matching exception+RVA (+ even product frames on stack scan) is **insufficient** for rebuild without concrete defective path + deterministic fix specification.

```
PRODUCT_DEFECT=NOT_PROVEN
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
```

## Method limits (explicit)

1. No cdb/WinDbg → no `!analyze -v` / true unwind `kv`.
2. Stack = exception CONTEXT + **RSP-forward module-mapped QWORD scan** (return-address candidates).
3. No PDB beside `RawrXD-Win32IDE-Native.exe` → product RVAs not symbolized to function/source.
4. Therefore `NATIVE_STACK=PARTIAL`, not `COMPLETE`.

## Next executable gate (still REBUILD=HELD)

1. Install Debugging Tools / use machine with cdb → `.ecxr; kv; lmvm comctl32` on both dumps; or ship PDB and SymFromAddr the product RVAs.
2. Optional same-SHA narrow (no source change): Cancel without Clear; WM_SETTEXT-only vs dual SetEdit — crash Y/N.
3. Authorize rebuild only after concrete defective path is named with stack/deterministic evidence + written `REBUILD_AUTHORIZED=1` receipt — prefer documenting authorization first; do not auto-rebuild.

Sealed ChatWindow / Token64 / GhostText remain closed. `PROMOTE=0`.
