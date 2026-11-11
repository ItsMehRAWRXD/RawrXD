# tip_ext_host_002 — EXT_SMOKE_RECEIPT

ASOF_UTC=2026-11-09T09:18:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

```
TIP_EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_002\RawrXD-Win32IDE-Native-Ext.exe
TIP_SHA256=8D8999CD722B3ED46E3E74D437C6ADF6CA4513E9C01128E02F9F0BF4BB579EAD
TIP_ALIAS=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_002\RawrXD-Win32IDE-Native.exe
PRIOR_FAIL_SHA=CF186F4C38D7DC1A3657E228CAEE611FB2D8B16EF7F2129444B1F2317B62F2A7
PRIOR_TIP_001_SHA=272199BE27AF3959D44C741C4F0337E9833291FB73346389167CC62000C189B8
FROZEN_A4F=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
FROZEN_A4F_UNTOUCHED=1
OVERWRITE_FROZEN_PACKAGE=FORBIDDEN
RUNLOG=logs\ext_smoke_run_20261109-041750.txt
HWND_LOG=logs\ext_smoke_hwnd_20261109-041750.txt
RECEIPT_A=logs\ext_receipt_A_20261109-041750.txt
RECEIPT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\ext_runtime_receipt.txt
SUMMARY=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\ext_smoke_summary_20261109-041750.json
FIXTURE=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\ext_hello
tip_fix=yes
ATTEMPTED_LOAD_SMOKE=1
EXT_LOAD=PASS
LAW=LOAD∧ACTIVATE∧CMD ⇒ PASS ; NOT_RUN!=PASS
```

## Gate matrix (measured)

| # | Gate | Result | Evidence |
|---|------|--------|----------|
| 1 | Process launch + main HWND survive | **PASS** | PID 36448; HWND `RawrXD_IDE_Window` `0x141060C`; EXIT=0 |
| 2 | VSIX / extension load path reachable | **PASS** | `--ext-dir` → `LOAD_OK=1` `INIT_OK=1` `EXTENSION_ID=rawrxd.ext-hello` |
| 3 | Activate minimal fixture extension | **PASS** | `ACTIVATE_OK=1` |
| 4 | Command registration probe | **PASS** | `--ext-cmd extHello.ping` → `CMD_OK=1` |
| 5 | Lifecycle cleanup / process exit clean | **PASS** | `--ext-quit` EXIT=0; `DEACTIVATE_OK=1`; lifecycle EXIT=0; `FORCE_KILL=0`; orphans=0 |
| 6 | Cancellation / fault isolation | **PASS** | `--ext-malformed` → `LOAD_OK=0` `FAULT_ISOLATED=1` process alive EXIT=0 |

## Runtime receipt (smoke A)

```
ATTEMPTED=1
INIT_OK=1
LOAD_OK=1
ACTIVATE_OK=1
CMD_OK=1
DEACTIVATE_OK=1
RELOAD_OK=1
FAULT_ISOLATED=0
PROCESS_ALIVE=1
EXTENSION_ID=rawrxd.ext-hello
DETAIL=
```

## Runtime receipt (smoke B malformed)

```
ATTEMPTED=1
INIT_OK=1
LOAD_OK=0
FAULT_ISOLATED=1
PROCESS_ALIVE=1
DETAIL=malformed rejected; process alive
```

## EXT_LOAD disposition

```
EXT_LOAD=PASS
```

Load + activate + gated cmd all measured OK on tip `8D8999CD…579EAD`.

## Source fixes landed (tip_fix=yes)

1. `bindVSCodeAPI`: seed `globalThis` + `vscode`; verify `commands` after binders; no same-object re-SetProperty
2. activate wrapper: hard-fail if `vscode.commands` missing; no empty stub
3. `activateExtension` / `executeScript`: release `m_extensionsMutex` before `JS_Eval` (MSVC non-recursive double-lock → prior `0xC0000409`)
4. `--ext-cmd` eval uses `globalThis.vscode`; path escape for `__filename`/`__dirname`

## SHA verify

| When | Tip SHA-256 | A4F frozen SHA-256 |
|------|-------------|--------------------|
| Stage | `8D8999CD…579EAD` | `A4F083DF…C6EF4E` |
| Post smoke | `8D8999CD…579EAD` (unchanged) | `A4F083DF…C6EF4E` (untouched) |

## Law

```
NOT_RUN ≠ PASS
LOAD_OK ∧ ACTIVATE_OK ∧ CMD_OK ⇒ EXT_LOAD=PASS (cmd gated)
PROMOTE=0
CERTIFIED=0
```
