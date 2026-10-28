# INVENTORY — WIN32IDE_FULL_SOURCE_AUDIT_002

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 PERFECT=0
TIP_SHA=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
ASOF_UTC=2026-10-28T17:00:00Z
```

## src/ by extension (filesystem)

| Ext | Count |
|-----|------:|
| cpp | 5591 |
| c | 192 |
| h | 1762 |
| hpp | 2758 |
| asm | 1328 |
| **sum (cpp/c/h/hpp/asm)** | **11631** |
| all files under src/ | 15099 |

Delta vs AUDIT_001: +6 cpp, +4 hpp, +10 all files.

## src/win32app/ by extension

| Ext | Count |
|-----|------:|
| cpp | 530 |
| c | 0 |
| h | 140 |
| hpp | 47 |
| asm | 10 |
| cpp+c+asm (linkable TUs) | **540** |

## Link truth (build_win32ide_link001 objs)

| Metric | Count |
|--------|------:|
| All RawrXD-Win32IDE .obj | **885** |
| win32app linked TUs (.obj) | **217** |
| win32app orphans (disk − linked) | **323** |

Artifacts: `linked_win32app_tus.txt`, `win32app_orphans.txt`.

## Pattern scan (files with TODO/FIXME/NOT_IMPLEMENTED/GateStub/FEATURE_FICTION/STUB)

| Tree | Files |
|------|------:|
| win32app | 28 |
| Headless* under win32app | 0 |
| agentic | 7 |
| deep2 | 15 |
| linked win32app with todoish | 16 / 217 |
| GateFiction( hits in command_handlers_comprehensive.cpp | **277** (GATED) |
| win32app empty .cpp | **0** |

## Orphan buckets (323)

| Bucket | N | Disposition |
|--------|--:|-------------|
| TEST | 14 | GATED_OMIT |
| STUB | 6 | GATED_OMIT |
| BRIDGE_GATED | 6 | GATED_OMIT (prior bridge sweeps) |
| GHOSTTEXT | 3 | GATED — ABSORB=NOT_AUTHORIZED |
| EXTENSION | 22 | OPEN (G17 product-intent) |
| DEBUGGER | 8 | OPEN (U14) |
| UI_PANEL | 25 | OPEN (U*) |
| HEADLESS_ALT | 7 | GATED/OPEN mix |
| PRODUCTION_GATE | 2 | OPEN/HELD (PromoteReady; crash_handler superseded) |
| OTHER | 230 | OPEN until adjudicated |
| **OPENISH (ext+dbg+ui+prod+other+headless)** | **294** | countable |
| **GATEDISH** | **29** | |

`rawr_crash_handler.cpp` → **GATED_OMIT_SUPERSEDED** by linked `Win32IDE_CrashReporter.cpp` + `main_win32.cpp` filters.
