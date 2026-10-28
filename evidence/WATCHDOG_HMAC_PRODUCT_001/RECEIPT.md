# RECEIPT — WATCHDOG_HMAC_PRODUCT_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T08:45:00Z
```

## Verdict

| Gate | Result |
|------|--------|
| MagBuf CRC (B04) | CLEARED_JOIN_CRC (prior) |
| HMAC product key path | SOURCE_WIRED_FAILCLOSED |
| RUNTIME_REACHED | **PASS** (object/link smoke; earned) |
| HMAC_PRODUCT | **PASS** (nonzero SHA256-derived cam_hmac_key after set_key; join) |
| NO_KEY fail-closed | **-1** (preserved) |
| CRC-as-HMAC | **0** (not used) |
| INIT_SELF_TEST_BLOCK | **-8** (held; RFC schedule ≠ KAT) |
| RELINK_REQUIRED | **1** (product EXE absorption of fixed Camellia + wired batch_005) |
| SMOKE_RELINK | **0** (this mission did not relink Win32IDE) |
| PROMOTE | 0 |

## Root cause (pre-fix)

`asm_camellia256_set_key` set `cam_initialized=1` but never wrote `cam_hmac_key` (derive lived only in `init` Step 6). `init` blocked at `self_test=-8` (simplified subkey schedule fails RFC 3713 Appendix A ciphertext compare). Smoke saw `CAM_HMAC_AFTER_SET_KEY=ZERO` + `INIT_SELF_TEST_BLOCK=-8`.

## Fix

`src/asm/RawrXD_Camellia256.asm`:

1. `set_key` derives `cam_hmac_key = SHA256(master \|\| "hmac-auth-key-v1")` before `cam_initialized=1` (same contract as init Step 6).
2. `cam_sha256` forces `and rsp,-16` + FP restore so CryptoAPI survives misaligned callers (`self_test→set_key`).

Smoke obj only: `evidence/WATCHDOG_HMAC_PRODUCT_001/RawrXD_Camellia256_e2e.obj`  
SHA256=`BB38AA5D5BB4627A86D42DBC4C796489B528835FFE8184A307B2446B3AE74B85`

## Runtime smoke (this mission)

- `_run_runtime_hmac.bat` → pass=8 fail=0 · SMOKE_EXIT=0
- `hmac_direct`/`hmac_baseline` prefix `E672E53B48E7676D` (match)
- `self_test_rc=-8` / `init_rc=-8` still held (not claimed PASS)
- Cite: `RUNTIME_run.log`, `RUNTIME_HMAC_PRODUCT_smoke_run.log`

## EXE SHA notes (honest)

| Field | Value |
|-------|-------|
| Prior mission-start seal | `89BFD6142CEE7A6AA537DF0297014E240C7CC55B142C230521527914469F8630` |
| Smoke touched Win32IDE link? | NO |
| User-noted concurrent SHA | `32C28BF7…` (external; not this smoke) |
| On-disk link001 EXE at seal time | `D121659F03EE1CF2D818035C182BCAC05B8AD32642F85D58457FB77044E95D50` |
| Tetrad claim on EXE SHA | NOT claimed by this mission |

## Paths

- `evidence/WATCHDOG_HMAC_PRODUCT_001/LAW.txt`
- `evidence/WATCHDOG_HMAC_PRODUCT_001/RECEIPT.md`
- `evidence/WATCHDOG_HMAC_PRODUCT_001/RUNTIME_REACHED.txt`
- `evidence/WATCHDOG_HMAC_PRODUCT_001/RUNTIME_run.log`
- `evidence/WATCHDOG_HMAC_PRODUCT_001/_run_runtime_hmac.bat`
- `src/asm/RawrXD_Camellia256.asm`

## Self-test follow-on (CAMELLIA_SELFTEST_RFC_001)

BLOCKED_DOCUMENTED — init self_test=-8 remains OPEN (RFC schedule/enc gap). HMAC product path still PASS. Tip EXE SHA unchanged (866E9D1B…). See evidence/CAMELLIA_SELFTEST_RFC_001/.
