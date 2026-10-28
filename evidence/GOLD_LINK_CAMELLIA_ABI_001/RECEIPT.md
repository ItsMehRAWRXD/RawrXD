# GOLD_LINK_CAMELLIA_ABI_001 RECEIPT

```
DISPOSITION=CLEARED
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
LOCAL_ONLY=1
RUNTIME_AUTH_E2E=NOT_RUN
WIN32IDE_EXE_REBUILD=0
WIN32IDE_EXE_SHA_HOLD=89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630
```

## Verdict

Prior `gold_link_closure` **key/iv 4-arg bool** ABI ≠ product **two-path int(path,path)** / Auth RCM2. Classified as dormant non-Win32IDE mismatch (Gold excludes `camellia256_bridge.cpp`; Win32IDE owned by Auth.obj). **CLEARED** by aligning/gating Gold C stubs — not by inventing RUNTIME_AUTH_E2E PASS.

## Code edit

`src/core/gold_link_closure.cpp` Camellia block:

| Before | After |
|--------|-------|
| `bool ...(path,path,key,iv)` XOR always | `#if !RAWR_HAS_MASM` `int ...(path,path)` XOR |
| Conflicts with Auth.obj when MASM linked | No C defs when `RAWR_HAS_MASM=1` |

## Object / link smoke (earned)

| Check | Result |
|-------|--------|
| CL_MASM1_EXIT | 0 — `CAMELLIA_AUTH_SYMBOLS_MASM1=NONE` |
| CL_MASM0_EXIT | 0 — External `encrypt_file` + `decrypt_file` |
| LINK_MASM0_EXIT | 0 |
| Source cite | two-path + gate; key/iv only in LAW comment |

Artifacts: `object_smoke.txt`, `dumpbin_masm0.txt`, `dumpbin_masm1.txt`, `abi_smoke.cpp`, `_object_smoke.bat`

## Explicit non-claims

- RUNTIME_AUTH_E2E = NOT_RUN (sibling / CAMELLIA_AUTH_ASM_BIND_001)
- PROMOTE = 0 · TIP_CLIMB = HOLD · CERTIFIED = 0
- Win32IDE EXE not rebuilt; Auth bind CLEARED_LINK_LEVEL undisturbed
