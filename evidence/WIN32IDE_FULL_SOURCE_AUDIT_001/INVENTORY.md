# INVENTORY — WIN32IDE_FULL_SOURCE_AUDIT_001

```
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 PERFECT=0
EXE_SHA=866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F
ASOF_UTC=2026-10-28T09:20:00Z
```

## src/ by extension (filesystem)

| Ext | Count |
|-----|------:|
| cpp | 5585 |
| c | 192 |
| h | 1762 |
| hpp | 2754 |
| asm | 1328 |
| **sum (cpp/c/h/hpp/asm)** | **11621** |
| all files under src/ | 15089 |

## src/win32app/ by extension

| Ext | Count |
|-----|------:|
| cpp | 524 |
| c | 0 |
| h | 140 |
| hpp | 43 |
| asm | 10 |
| cpp+c+asm (linkable TUs) | 534 |

## CMake WIN32IDE_SOURCES (comment-stripped net)

| Metric | Count |
|--------|------:|
| WIN32IDE_SOURCES net (cpp/c/rc paths) | **806** |
| of which win32app/ | **203** |
| win32app orphans (on disk, not in net) | **332** |
| Parse note | earlier comment-inclusive parse was 845; `# crypto_stubs.cpp` etc. excluded |

MASM product objs (Camellia256 / Camellia256_Auth / Watchdog) link via dedicated ASM rules / `.obj` — not counted in the 806 `.cpp` net.

## Key membership (net)

| Surface | In WIN32IDE net? |
|---------|------------------|
| `rawrxd_subsystem_api.cpp` (Mode/SO/AD) | YES |
| `unlinked_symbols_batch_005.cpp` | YES |
| `unlinked_symbols_batch_010/011.cpp` | NO (CMake omit) |
| `crypto_stubs.cpp` | NO (comment-only REMOVED) |
| `command_handlers_comprehensive.cpp` | YES |
| `win32ide_watchdog_init.cpp` | YES |
| `Win32IDE_Watchdog.cpp` | YES |
| `camellia256_bridge.cpp` | YES |
| `agentic_bridge.cpp` / `Win32IDE_AgenticBridge.cpp` | YES |
| `Win32IDE_ShellLayout.cpp` | YES |
| HeadlessIDE + Tool/Gui/FileAliases | YES |
| `Win32IDE_AgenticFeatures.cpp` | NO (GATED_OMIT) |
| `Win32IDE_LoRAKernelBridge.cpp` | NO (GATED_OMIT) |
| `Win32IDE_LogpointBridge.cpp` | NO (GATED_OMIT) |
| `Win32IDE_SidebarBridge.cpp` | NO (GATED_OMIT) |
| `Win32IDE_AgentBridge_Init.cpp` | NO (GATED_OMIT) |

## Orphan examples (GATED_OMIT / non-product)

```
src/win32app/Win32IDE_AgenticFeatures.cpp
src/win32app/Win32IDE_LoRAKernelBridge.cpp
src/win32app/Win32IDE_LogpointBridge.cpp
src/win32app/Win32IDE_SidebarBridge.cpp
src/win32app/Win32IDE_AgentBridge_Init.cpp
src/win32app/agentic_bridge_headless.cpp
```

Full orphan list: `evidence/_tmp_win32app_orphans.txt` (working scratch; 332 lines).
Net list: `evidence/_tmp_win32ide_sources_net.txt` (806 lines).
