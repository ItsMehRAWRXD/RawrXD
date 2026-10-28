# WIN32IDE_BRIDGE_XOR_LAW_001 RECEIPT

```
DISPOSITION=GATED_OMIT
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
LOCAL_ONLY=1
CMAKE_OMIT=1
RUNTIME_AUTH_E2E=NOT_RUN
WIN32IDE_EXE_REBUILD=0
WIN32IDE_EXE_SHA_HOLD=89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630
```

## Verdict

`src/core/win32ide_asm_kernel_bridge.cpp` XOR Camellia leftovers are **dormant**: **zero** `CMakeLists.txt` references (`MATCH_COUNT=0 CMAKE_OMIT=1`). Not in Win32IDE link. Product Auth ownership remains `RawrXD_Camellia256_Auth.obj` (CAMELLIA_AUTH_ASM_BIND_001). Disposition **GATED_OMIT** — not PASS, not silent stub success.

## Code edit

Header + Camellia block cite this LAW; file+buf XOR remain under `#if !defined(RAWR_HAS_MASM)` so accidental re-link with `RAWR_HAS_MASM` defined does not redefine Auth symbols.

## Cite

| Fact | Evidence |
|------|----------|
| CMake omit | `cmake_omit_cite.txt` MATCH_COUNT=0 |
| Source gate | lines citing WIN32IDE_BRIDGE_XOR_LAW_001 / GATED_OMIT |
| Product owner | CAMELLIA_AUTH_ASM_BIND_001 map → Auth.obj |

## Explicit non-claims

XOR present in unlinked source ≠ RUNTIME_AUTH_E2E · PROMOTE=0 · CERTIFIED=0 · NOT_RUN≠PASS
