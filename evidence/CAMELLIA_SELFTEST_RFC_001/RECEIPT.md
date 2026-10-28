# CAMELLIA_SELFTEST_RFC_001 RECEIPT

## Disposition

| Field | Value |
|------|------|
| DISPOSITION | **BLOCKED_DOCUMENTED** |
| SELF_TEST_RFC | OPEN (`self_test_rc=-8`) |
| HMAC_PRODUCT | PASS (independent) |
| ASM_PATCH | 0 |
| WIN32IDE_RELINK | 0 |
| EXE_SHA_CHANGED | **0** |
| TIP_EXE | `G:\~dev\rawrxd\build_win32ide_link001\bin\RawrXD-Win32IDE.exe` |
| TIP_SHA256 | `866E9D1B3B6E617B7C6001EA3BFC754002C0CE61F8880FF6294C95B86E6A601F` |
| TIP_TETRAD | UNTOUCHED (not re-sealed; not invalidated) |
| PROMOTE | 0 |
| TIP_CLIMB | HOLD |
| CERTIFIED | 0 |

## Trace

- Owner: `src/asm/RawrXD_Camellia256.asm` — `asm_camellia256_self_test` → `@@st_fail`
- Init gate: `asm_camellia256_init` → `@@init_selftest_fail` (−8)
- Auth: `RawrXD_Camellia256_Auth.asm` — no self_test ownership
- Cause: non-RFC subkey schedule (52-slot invented ROL mixer) + encrypt indexing; KAT encrypt compare fails
- Why not fixed this mission: schedule-only patch insufficient; full RFC rewrite + remapped enc/dec would relink tip and invalidate tetrad without sibling re-seal

## Product-path LAW

HMAC watchdog product uses `set_key` → SHA256 domain-separated `cam_hmac_key` → `get_hmac_key` / baseline join. That path does **not** require `asm_camellia256_init` or RFC cipher KAT. `HMAC_PRODUCT PASS ≠ self_test PASS`.

## Smoke (cmd bat)

```
evidence/WATCHDOG_HMAC_PRODUCT_001/_run_runtime_hmac.bat
```

Cite: `SMOKE_SELFTEST_reconfirm.log`

```
self_test_rc=-8
set_key_rc=0
HMAC_PRODUCT=PASS
INIT_SELF_TEST_BLOCK=-8
```

## Next gate (held)

RFC multi-file key schedule + enc/dec remap → KAT smoke → optional Win32IDE relink → sibling tetrad re-seal. `PROMOTE=0`.
