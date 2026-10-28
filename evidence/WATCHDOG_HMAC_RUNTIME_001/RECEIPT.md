# RECEIPT — WATCHDOG_HMAC_RUNTIME_001

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
| Link smoke (Watchdog_from_source.obj + Camellia256.obj) | PASS (BUILD_OK) |
| asm_watchdog_init → get_hmac_key | RUNTIME_REACHED=**PASS** (earned) |
| NO_KEY fail-closed | **2** (nonzero) |
| get_baseline / verify | Exercised (baseline rc=0 after NO_KEY status; verify rc=-1) |
| HMAC_FULL (CryptoAPI baseline) | FAIL / default SKIPPED (`--full` AVs) |
| HMAC_PRODUCT | NOT_CLAIMED (cam_hmac_key ZERO after set_key) |
| Win32IDE relink (this mission) | **0** |
| PROMOTE | **0** |

## Artifacts

| Artifact | SHA256 / size |
|----------|---------------|
| Watchdog_from_source.obj (this seal, RSP-align fix) | `C0EC33E91A98D004F2879220C2D8420FD7D90AAE9D333367D3B8940247C14DF3` / 13264 |
| Camellia256.obj (product bind, untouched) | `6F960ABE05945C08A5FE94590B3369AE68A8FD69F54077E012115D6BFFA1FB0E` / 31502 |
| runtime_hmac_asm_smoke.exe | `C323BB76A470EC0A35EC786D9672C81B75FA7D4E9D4331AC0626AFAE60DB4C88` |
| OBSERVED build_win32ide_link001 EXE (not rebuilt here) | `D121659F03EE1CF2D818035C182BCAC05B8AD32642F85D58457FB77044E95D50` |

Prior PRODUCT_001 cited EXE `89BFD614…`. Observed tree EXE differs; this mission did not invoke Win32IDE link/ninja. Divergence recorded fail-closed — not a new tetrad claim.

## Smoke log (earned lines)

```
pre_ready asm_watchdog_init_rc=2 (expect NO_KEY=2)
RUNTIME_REACHED=PASS
NO_KEY_FAILCLOSED=2
HMAC_PRODUCT=NOT_CLAIMED
PROMOTE=0
SMOKE_EXIT=0
```

## Product ASM note

`src/asm/RawrXD_Watchdog.asm`: `sub rsp` sizes in init/verify/hmac adjusted (+8) so Win64 calls see `RSP%16==0` after `SAVE_NONVOL`+`rbp`. Evidence obj reassembled here; sealed Win32IDE EXE not relinked.

## Paths

- `evidence/WATCHDOG_HMAC_RUNTIME_001/LAW.txt`
- `evidence/WATCHDOG_HMAC_RUNTIME_001/RECEIPT.md`
- `evidence/WATCHDOG_HMAC_RUNTIME_001/_build_runtime_hmac_asm.bat`
- `evidence/WATCHDOG_HMAC_RUNTIME_001/_run_runtime_hmac_asm.bat`
- `evidence/WATCHDOG_HMAC_RUNTIME_001/runtime_hmac_asm_smoke.c`
- `evidence/WATCHDOG_HMAC_RUNTIME_001/RUNTIME_run.log`
- Prior SOURCE_WIRED: `evidence/WATCHDOG_HMAC_PRODUCT_001/`
- Prior object bind: `evidence/WATCHDOG_ASM_BIND_001/`
