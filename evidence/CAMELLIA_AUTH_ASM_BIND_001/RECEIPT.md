# CAMELLIA_AUTH_ASM_BIND_001 RECEIPT

## Verdict

| Field | Value |
|------|------|
| BIND_STATUS | SOURCE_WIRED + OBJECT_SMOKE + LINK_SMOKE |
| SYNTHETIC | **0** (Win32IDE Auth file/buf path) |
| PROMOTE | **0** |
| TIP_CLIMB | HOLD |
| CERTIFIED | 0 |
| RUNTIME_AUTH_E2E | **PASS** (smoke 16/0; cite RUNTIME_E2E_run.log) |
| G06 | not reopened |
| Digestion_scanner | out |
| Mode* | out this turn (next gap) |

## Symbol map

| Symbol | Pre-bind owner | Post-bind owner | ABI |
|--------|----------------|-----------------|-----|
| asm_camellia256_auth_encrypt_file | batch_005 XOR | RawrXD_Camellia256_Auth.obj | `int(const char*, const char*)` |
| asm_camellia256_auth_decrypt_file | batch_005 XOR | RawrXD_Camellia256_Auth.obj | `int(const char*, const char*)` |
| asm_camellia256_auth_encrypt_buf | (unresolved / unused in map) | RawrXD_Camellia256_Auth.obj | bridge RCM2 buf |
| asm_camellia256_auth_decrypt_buf | (unresolved / unused in map) | RawrXD_Camellia256_Auth.obj | bridge RCM2 buf |

Map excerpt (post-link):

```
0001:01d56840       asm_camellia256_auth_encrypt_file 0000000141d57840 f   RawrXD_Camellia256_Auth.obj
0001:01d56ba0       asm_camellia256_auth_decrypt_file 0000000141d57ba0 f   RawrXD_Camellia256_Auth.obj
0001:01d56f20       asm_camellia256_auth_encrypt_buf 0000000141d57f20 f   RawrXD_Camellia256_Auth.obj
0001:01d57040       asm_camellia256_auth_decrypt_buf 0000000141d58040 f   RawrXD_Camellia256_Auth.obj
```

## What changed

1. Restored `src/asm/RawrXD_Camellia256_Auth.asm` from `Full Source` (was END-only 5B stub; now 41951B RCM2 Auth engine). SHA256=8979B38EEDAEA546D1914A864ABCC70A7C081F901EBD56046D55FC7D7461338E
2. Gated batch_005 XOR `asm_camellia256_auth_{en,de}crypt_file` under `#if !defined(RAWR_HAS_MASM)` (same pattern as omega).
3. Updated batch_019 ownership comment (reference-only TU).
4. Object smoke: ml64 assembled Auth ASM (evidence obj + buildtree obj with 4 External exports).
5. Forced Auth.obj rebuild in `build_win32ide_link001` (ninja had stale zero-export 840B obj).
6. Relinked `RawrXD-Win32IDE.exe` LINK_EXIT=0. Map ownership moved to Auth.obj.

## Binaries

| Artifact | SHA256 / size |
|----------|---------------|
| POST_BIND EXE | 89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630 / 331629056 |
| Auth.obj (buildtree) | 74D031802C556BE608F3EB6E193A5F437499D876BAEA902A7274486961E2FB2D / 21749 |
| Auth.obj (evidence smoke) | AAB20EB2BDD68C547478E6DCE1E3DC64CC9175FAB939FC74A198F2518BB0C3CA |
| PRIOR LIVE_TETRAD sealed EXE | 4A5D6B31… (historical; PRE_LINK removed during bind; exact backup not found) |

## RUNTIME_AUTH_E2E (earned)

| Field | Value |
|------|------|
| RUNTIME_AUTH_E2E | PASS |
| SMOKE_EXIT | 0 |
| pass/fail | 16 / 0 |
| XOR_PATH | 0 |
| PROMOTE | 0 |
| Log | `RUNTIME_E2E_run.log` |
| Disposition | `RUNTIME_E2E_DISPOSITION.txt` |

Harness: `runtime_auth_e2e_smoke.exe` linked Auth_e2e.obj + Camellia256_e2e.obj (no Win32IDE rebuild).
ODS stub required (set_key Win64 stack misalign → kernelbase AV). Tamper observed rc=1 (VirtualFree clobbers -7).

## Remaining gaps (next)

1. Mode* stubs (subsystem_api) — independent; not this turn.
2. Product ASM: align RSP before OutputDebugStringA / preserve EAX across VirtualFree on auth error paths.
3. gold_link_closure key/iv ABI mismatch vs product two-path Auth (sibling / non-Win32IDE).
4. win32ide_asm_kernel_bridge.cpp XOR leftovers — **not Win32IDE-linked** (omit clear; LAW note).
5. MULTI_FAMILY still open; PROMOTE=0; LIVE_TETRAD historical seal unchanged as evidence text.

## Evidence paths

- `evidence/CAMELLIA_AUTH_ASM_BIND_001/LAW.txt`
- `evidence/CAMELLIA_AUTH_ASM_BIND_001/RECEIPT.md`
- `evidence/CAMELLIA_AUTH_ASM_BIND_001/RUNTIME_E2E_run.log`
- `evidence/CAMELLIA_AUTH_ASM_BIND_001/RUNTIME_E2E_DISPOSITION.txt`
- `evidence/CAMELLIA_AUTH_ASM_BIND_001/map_auth_symbols.txt`
- `evidence/CAMELLIA_AUTH_ASM_BIND_001/ml64_smoke.out`
- `evidence/CAMELLIA_AUTH_ASM_BIND_001/dumpbin_symbols.txt`
- `evidence/CAMELLIA_AUTH_ASM_BIND_001/ninja_win32ide_relink.log`
- `evidence/CAMELLIA_AUTH_ASM_BIND_001/link_smoke.txt`
