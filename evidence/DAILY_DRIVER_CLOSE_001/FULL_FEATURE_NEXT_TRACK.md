# Full-feature next track (preserve slim baseline)

ASOF_UTC=2026-11-09T07:54:00Z
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0

```
IMMUTABLE_BASELINE=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
PACKAGE_EXE=F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe
OVERWRITE_FROZEN_PACKAGE=FORBIDDEN
STAGE_NEW_WORK_UNDER=package\tip_*\ OR new evidence seal ID
```

## Separated objectives

1. **Preserve** slim daily-driver baseline `A4F083DF…` (IMMUTABLE=1).
2. **Finish** full-feature IDE on new tip stages without regressing that baseline.

## Ordered track

1. Native ExtensionHost / VSIX load integrate + same-SHA smoke.
2. Autonomous editing + tool execution acceptance.
3. Debugging, sidebar, advanced IDE features validation.
4. Full-product integration + endurance (not transfer 3B72 seals).
5. Separately hashed full-feature release candidate.

## Progress note (FULL_FEATURE_EXTENSIONHOST_001)

ASOF_UTC=2026-11-09T08:00:00Z

```
STEP1_SURVEY=DONE
STEP1_TIP_STAGE_PLAN=DONE
STEP1_SOURCE_WIRE=NOT_FEASIBLE_ONE_TURN
STEP1_TIP_EXE=NONE
STEP1_TIP_SHA_OR_NONE=NONE
STEP1_EXT_LOAD=NOT_RUN
FROZEN_A4F_UNTOUCHED=1
EVIDENCE=F:\rawrxd\evidence\FULL_FEATURE_EXTENSIONHOST_001\
GAP=missing quickjs_extension_host / vscode_extension_api / ExtensionLoader TUs;
    js_extension_host only under ~dev mirror; slim RAWRXD_NATIVE_IDE_SOURCES has no EXT link
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
```

Slim seals unchanged. EXT out-of-scope for slim ≠ invent EXT PASS.

## Rollback bak identity (SHA-verified)

| Artifact | Content SHA-256 | Size |
|----------|-----------------|------|
| `…18FA04F9.bak` | `18FA04F9…` (filename matches) | 2509824 |
| `…9C910599.bak` (label) | `CE4F471D…` (**filename does not match**) | 2594304 |

Restore only after re-hash. Prefer renaming the CE4F bak to its content SHA for operators.

## Progress note (FULL_FEATURE_EXTENSIONHOST_001 sequence 1-3)

ASOF_UTC=2026-11-09T08:30:00Z

```
STEP1_RESTORE_TUS=DONE
STEP1_CMAKE_TIP_EXT=DONE
STEP1_TIP_EXE=DONE
STEP1_TIP_SHA=272199BE27AF3959D44C741C4F0337E9833291FB73346389167CC62000C189B8
STEP1_TIP_PATH=package\tip_ext_host_001\RawrXD-Win32IDE-Native.exe
STEP1_EXT_LOAD=NOT_RUN
FROZEN_A4F_UNTOUCHED=1
EVIDENCE=F:\rawrxd\evidence\FULL_FEATURE_EXTENSIONHOST_001\
RECEIPT=TIP_BUILD_RECEIPT.md
BUILD_ALONE_NE_EXT_PASS=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
NEXT=product wire initialize+loadVSIX then same-SHA EXT smoke
```

Slim A4F package unchanged. Tip binary != EXT_LOAD PASS.

## Progress note (FULL_FEATURE_EXTENSIONHOST_001 sequence 4-5 EXT smoke)

ASOF_UTC=2026-11-09T08:40:24Z

```
STEP1_TIP_SHA=272199BE27AF3959D44C741C4F0337E9833291FB73346389167CC62000C189B8
STEP1_TIP_SHA_PRE_POST_MATCH=1
STEP1_LAUNCH_HWND=PASS
STEP1_LIFECYCLE_EXIT=PASS
STEP1_EXT_LOAD=NOT_RUN
STEP1_VSIX_LOAD_PATH=NOT_RUN
STEP1_ACTIVATE=NOT_RUN
STEP1_CMD_REG=NOT_RUN
STEP1_CANCEL_FAULT=NOT_RUN
ATTEMPTED_LOAD_SMOKE=0
FROZEN_A4F_UNTOUCHED=1
EVIDENCE=F:\rawrxd\evidence\FULL_FEATURE_EXTENSIONHOST_001\
RECEIPT=EXT_SMOKE_RECEIPT.md
RUNLOG=logs\ext_smoke_run_20261109-034019.txt
BUILD_ALONE_NE_EXT_PASS=1
LOCUS=installExtension PLACEHOLDER; Win32IDE_Core not in Native sources; loadVSIX strings absent from tip EXE image despite EXT obj
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
NEXT=product wire initialize+loadVSIX then same-SHA EXT load/activate smoke
```

Slim A4F package unchanged. Launch PASS != EXT_LOAD PASS.
