# EXTENSIONHOST_GATE — FULL_FEATURE_FINAL_COMPLETION_001

ASOF_UTC=2026-11-09T10:12:30Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0

## Final candidate (required)

```
TIP_SHA=CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4
TIP_EXE=candidates\tip_final_integ_002\RawrXD-Win32IDE-Native-Ext.exe
TIP_CONFIG=RelWithDebInfo
BUILD=build_tip_debug_rel
EXT_LOAD=PASS
INIT_OK=1
LOAD_OK=1
ACTIVATE_OK=1
CMD_OK=1
DEACTIVATE_OK=1
RELOAD_OK=1
MALFORMED_FAULT_ISOLATED=1
EXIT_A=0
FORCE_KILL=0
EXTENSION_ID=rawrxd.ext-hello
RUNLOG=logs\ext_smoke_run_20261109-051316.txt
RUNLOG_ALIAS=logs\ext_smoke_tip_final_integ_002.txt
ORPHANS=0
RECEIPT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\ext_runtime_receipt.txt
FROZEN_A4F_UNTOUCHED=1
```

## Prior integ tip (not controlling)

```
PRIOR_TIP=tip_final_integ_001
PRIOR_SHA=7582A0C9899E0EA587E98F6343BBF8F28364713701CA91CF58319C20D46E2F58
PRIOR_EXT_LOAD=FAIL
PRIOR_REASON=ext_runtime_receipt not written after --ext-dir/--ext-cmd/--ext-quit
NO_CROSS_SHA_PASS_INHERITANCE=1
```

## Historical (reference only; no inheritance)

```
HISTORICAL_TIP_SHA=8D8999CD722B3ED46E3E74D437C6ADF6CA4513E9C01128E02F9F0BF4BB579EAD
HISTORICAL_EXT_LOAD=PASS
NO_CROSS_SHA_PASS_INHERITANCE=1
```

## Repair measured into tip_final_integ_002

1. Tip rebuild absorbed ExtHost wire trampoline (`--ext-cmd` via `invokeRegisteredCommand`; intermediate receipt).
2. RelWithDebInfo Native-Ext staged under `candidates\tip_final_integ_002\` (never A4F).
3. Fixture `ext_hello` synced to no-MessageBox ping (ONESHOT copy).

```
EXT_LOAD=PASS
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
```
