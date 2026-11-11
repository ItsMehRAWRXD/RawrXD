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
