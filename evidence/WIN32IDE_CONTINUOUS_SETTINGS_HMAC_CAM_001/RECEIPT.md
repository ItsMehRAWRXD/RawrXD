# RECEIPT — WIN32IDE_CONTINUOUS_SETTINGS_HMAC_CAM_001

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
ABSORB_GHOSTTEXT=NOT_AUTHORIZED
NO_INVENT_PASS=1
ASOF_UTC=2026-10-28T17:11:30Z
WORKSPACE=G:\~dev\rawrxd
```

## Tip / candidate

| Role | Path | SHA256 |
|------|------|--------|
| TIP authority | `evidence/TIP_FREEZE_001/bin/RawrXD-Win32IDE.exe` | `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145` |
| Candidate / GhostText witness | `build_win32ide_link001/bin/RawrXD-Win32IDE.exe` | `B4212E46598F6490241A531C88C8D9A8DA37532B8C940A2C38BB35226C5D869F` |

Binary string scan (tip + cand): `hmac-auth-key-v1=FOUND`, `LoadUnlocked OK=FOUND`. Tip also `RCM2=FOUND`. Symbol *names* as ASCII are often absent in release PE (STR_MISS ≠ unlink).

## Runtime smoke re-verify (this mission)

| Smoke | Exit | Key lines | Disposition |
|-------|------|-----------|-------------|
| `WATCHDOG_HMAC_PRODUCT_001/_run_runtime_hmac.bat` | 0 | pass=8 fail=0; HMAC_PRODUCT=PASS; INIT_SELF_TEST_BLOCK=-8; CRC_AS_HMAC=0 | **RUNTIME_REACHED=PASS** (object smoke) |
| `WATCHDOG_HMAC_RUNTIME_001/_run_runtime_hmac_asm.bat` | 0 | pass=8 fail=0; NO_KEY=2; HMAC_PRODUCT=NOT_CLAIMED; HMAC_FULL=SKIPPED | **RUNTIME_REACHED=PASS** (ASM init path smoke) |
| `CAMELLIA_AUTH_ASM_BIND_001/_run_runtime_auth_e2e.bat` | 0 | pass=16 fail=0; XOR_PATH=0; RCM2 magic | **RUNTIME_AUTH_E2E=PASS** (obj smoke) |
| Self-test reconfirm (same HMAC product log) | — | `self_test_rc=-8` | **OPEN / BLOCKED_DOCUMENTED** |

Cite: sibling `RUNTIME_run.log` / `RUNTIME_E2E_run.log` under those evidence dirs (rebuilt+rerun this turn).

## SettingsManager deadlock-free

| Gate | Result |
|------|--------|
| Source | `Initialize`/`Shutdown` hold `m_mutex` once; call `LoadUnlocked`/`SaveUnlocked` |
| Nested lock | **CLEARED** in source |
| Tip string | `LoadUnlocked OK` present in 748B |
| Tip RUNTIME | `TIP_GUI_CREATEWINDOW_748B_001` stderr: LoadUnlocked OK → Initialize OK |
| MAIN_HWND 748B | **EARNED** (`0x7703AE`; cite that seal; this mission did not re-launch) |

## Fail-closed stubs / shadows

| Item | Status |
|------|--------|
| AgenticFeatures Camellia C stubs | Gated `#if !RAWR_HAS_MASM` (`AGENTIC_CAMELLIA_STUB_GATE_001`) |
| `watchdog_stubs.cpp` | Orphan theater file; **not** product map owner |
| Product `asm_watchdog_init` | **C MagBuf** (`win32ide_watchdog_init.cpp`) shadows MASM PUBLIC — OPEN |
| Product HMAC join | batch_005 `get_baseline` → `asm_camellia256_get_hmac_key` (Camellia.obj) |
| GhostText absorb into tip | **NOT_AUTHORIZED** |
| PROMOTE / CERTIFIED | **0** |

## Held open (do not invent PASS)

1. `self_test=-8` RFC KAT / schedule (`CAMELLIA_SELFTEST_RFC_001`)
2. MASM `asm_watchdog_*` entry dual-link (requires gating C exports; tip freeze forbids casual relink)
3. In-EXE tip tetrad HMAC/auth E2E on 748B this mission — **NOT_RUN**
4. TPS / MULTI_FAMILY / PromoteReady conjunction

## Paths

- `evidence/WIN32IDE_CONTINUOUS_SETTINGS_HMAC_CAM_001/LAW.txt`
- `evidence/WIN32IDE_CONTINUOUS_SETTINGS_HMAC_CAM_001/RECEIPT.md`
- `evidence/WIN32IDE_CONTINUOUS_SETTINGS_HMAC_CAM_001/DISPOSITIONS.txt`
- Priors: `TIP_GUI_CREATEWINDOW_FIX_001/002`, `WATCHDOG_*`, `CAMELLIA_*`, `TIP_FREEZE_001`
