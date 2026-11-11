# INTEG005_DISK_RESTORE_FAIL_RECEIPT — 7504BAC4 bit-identical restore

ASOF_UTC=2026-11-09T13:17:00Z
MOTD_ACK=1

```
RESTORE=FAIL
RESTORE_KIND=DISK_RESTORE_FAIL
TARGET_SHA256=7504BAC45CDBA3DACF7A8CE30785971082C88101CC94586577771DE0C0FBAB48
RESTORE_SOURCE=NOT_FOUND
DISK_SHA256=27E2263E44F681C3FE0EAB19A8FC8228C10668B8A1742A15BB19E8F6E66C3FFC
DISK_PATH=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_005\RawrXD-Win32IDE-Native-Ext.exe
BIT_IDENTICAL=0
CROSS_SHA_PASS_INHERITANCE=0
NO_INHERIT_EXT=1
NO_INHERIT_PROBLEMS_UI=1
NO_INHERIT_CHAT=1
TERM=NOT_RUN
TERM_INHERITANCE_STOPPED=1
G3_TERM_REVERIFY=NOT_RUN
REASON=bit-identical 7504BAC4 EXE absent on disk; MSVC rebuild cannot reproduce sealed SHA
CONTROLLING_TIP=CC79
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1
TIP_002_UNTOUCHED=1
TIP_004_FROZEN_STOP_OVERWRITE=RESPECTED
TIP_005_NOT_OVERWRITTEN_WITH_NON_7504=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
CONSOLE_RENDERING=FAIL
```

## Search (exhaust)

- `F:\rawrxd` recursive `RawrXD-Win32IDE*.exe` Get-FileHash: **FOUND_COUNT=0** for `7504BAC4…`
- `G:\~dev` recursive `RawrXD-Win32IDE*.exe` Get-FileHash: **FOUND_COUNT=0** for `7504BAC4…` (search exit 0)
- tip siblings + `build_tip_debug_rel\bin` hold `27E2263E…` (or other non-target SHAs)
- Recycle Bin / bak / `*7504*` named EXE: none matching target
- Measured receipts remain under `INTEG005_*_REVERIFY_RECEIPT.md` for `7504BAC4…` only — **do not transfer** to `27E2263E…`

## Rebuild attempt (aborted — cannot bit-match)

- Timeline: `main_win32` DestroyWindow @ ~07:47; EXT smoke on `7504BAC4…` @ 07:50:13; `stripVtForRichEdit` landed in panel @ 07:51:17; VT overwrite to `27E2263E…` @ 07:54:32 / freeze 07:59:49
- Attempted 7504-era tree: keep DestroyWindow; `git checkout HEAD -- Win32IDE_PowerShellPanel.cpp` (stripVt off)
- `ninja RawrXD-Win32IDE-Native-Ext` @ `build_tip_debug_rel` emitted `build log version is too new; starting over` → full 341-target rebuild (not incremental) — **aborted**
- Source panel restored from `_restore_scratch\Win32IDE_PowerShellPanel.cpp.CURRENT` (stripVt back)
- tip_005 EXE **not** replaced with non-7504 rebuild output (FROZEN `27E2263E…` left on disk)

## Disposition

```
NEXT_GATE=REBUILD_NEW_SHA_THEN_REQUEUE_EXT_PROBLEMS_CHAT
  OR locate external bit-identical 7504BAC4 backup
BLOCKED_FOR_G3_TERM_REVERIFY_ON_7504=1
REQUEUE_ON_NEW_SHA=Ext+Problems+Chat+Term (no PASS inherit)
PROMOTE=0
```
