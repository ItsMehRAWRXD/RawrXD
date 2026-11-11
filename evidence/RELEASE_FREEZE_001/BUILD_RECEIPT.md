# BUILD_RECEIPT — tip_freeze_001 (PSCM PowerShell repair)

```
ASOF_UTC=2026-11-09T18:26:00Z
ONE_BUILD_ONE_SHA=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82%_UNCHANGED
A4F_IMMUTABLE=1
NO_CROSS_SHA_PASS=1
E6CF_RESTORE=HELD
```

## Identity

| Field | Value |
|-------|-------|
| Candidate tip | `tip_freeze_001` |
| Staged EXE | `F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\RawrXD-Win32IDE-Native-Ext.exe` |
| Seal copy | `candidates\tip_freeze_002\RawrXD-FreezeSeal-430B2108.exe` |
| **SHA-256** | `430B21087018165B898F9B224896CCE3EE1273F10582EFA60E44705E25C4B547` |
| Prior SHA (replaced) | `35C22E8AAFC1E9B30E40C2505AF7B4DEB66BDFB73D56B75D31C937D8C70D8563` |
| Size (bytes) | `2249728` |
| Build dir | `F:\rawrxd\.worktrees\release-freeze-001\build_release_freeze_001` |
| Repair | `WM_COPYDATA` / `kRawrxdPowerShellCopyDataCmd` (`PSCM`) in `Win32IDE_PowerShellPanel.cpp` + `Win32IDE.h` |
| Rebuild log | `artifacts\tip_freeze_001_pscm_rebuild.log` |

## Measured on this SHA

| Gate | Result | Receipt |
|------|--------|---------|
| PowerShell `ls` in-pane | **PASS** (342→3947; Directory listing) | `artifacts\FREEZE001_PS_RECEIPT.txt` |
| PS chat clean | **PASS** | same |
| Four-panel 1–17 | **FAIL_CLOSED_GAPS** (6 PASS / 7 FAIL) | `artifacts\FOUR_PANEL_1_17_RECEIPT.txt` |
| EXACTLY_ONCE / H57 / H21 | **NOT_VERIFIED on 430B** (35C22 receipts invalidated) | remasure required |

```
CANDIDATE_SHA=430B21087018165B898F9B224896CCE3EE1273F10582EFA60E44705E25C4B547
LS_IN_PANE=PASS_ON_430B2108
FOUR_PANEL=FAIL_CLOSED_GAPS
35C22_PASS_NE_430B_CREDIT=1
1046C2B8_PS_PASS_PRESERVED_SEPARATE=1
FREEZE001=NOT_PASS
PROMOTE=0
```
