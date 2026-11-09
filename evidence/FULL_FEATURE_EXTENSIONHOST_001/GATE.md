# FULL_FEATURE_EXTENSIONHOST_001 — GATE

ASOF_UTC=2026-11-09T12:15:00Z
TRACK=FULL_FEATURE Native ExtensionHost / VSIX load
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
INVENT_PASS=0
NO_CROSS_SHA_PASS_INHERITANCE=1

```
IMMUTABLE_BASELINE_SHA=A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E
FROZEN_A4F_UNTOUCHED=1
OVERWRITE_FROZEN_PACKAGE=FORBIDDEN
```

## This-lane tip seal ([Rebuild tip EXT activate fix](3d02f68e-7f16-4fac-8b73-8bd50c3161c2))

```
SEALED_TIP=package\tip_ext_host_002\
SEALED_SHA=8D8999CD722B3ED46E3E74D437C6ADF6CA4513E9C01128E02F9F0BF4BB579EAD
EXT_LOAD=PASS
INIT_OK=1 LOAD_OK=1 ACTIVATE_OK=1 CMD_OK=1
FAULT_ISOLATED_MALFORMED=1
EXIT=0 tip_fix=yes
RUNLOG=logs\ext_smoke_run_20261109-041750.txt
SMOKE_RECEIPT=EXT_SMOKE_RECEIPT.md
FOLLOWUP=ABSORBED_AS_PRIOR — oneshot controlling moved to tip_final_* (see ONESHOT EXTENSIONHOST_GATE)
```

| # | Gate | Result | Evidence |
|---|------|--------|----------|
| 1 | Launch / HWND | **PASS** | HWND `0x141060C`; EXIT=0 |
| 2 | Ext-dir load | **PASS** | INIT_OK=1 LOAD_OK=1 |
| 3 | Activate fixture | **PASS** | ACTIVATE_OK=1 |
| 4 | Command invoke | **PASS** | CMD_OK=1 `extHello.ping` |
| 5 | Lifecycle exit | **PASS** | EXIT=0 DEACTIVATE_OK=1 orphans=0 |
| 6 | Malformed reject | **PASS** | FAULT_ISOLATED=1 |

## Tip ladder (this lane)

| Stage | SHA | EXT_LOAD |
|-------|-----|----------|
| tip_ext_host_001 | 272199BE… | NOT_RUN |
| tip_ext_host_002 (prior fail) | CF186F4C… | FAIL (activate) |
| tip_ext_host_003 | 0A53EA74… | PASS (CMD_OK=0) |
| tip_ext_host_002 (sealed) | **8D8999CD…** | **PASS** (CMD_OK=1) |

## Law

```
NOT_RUN ≠ PASS
NO_CROSS_SHA_PASS_INHERITANCE=1
THIS_LANE_PASS ≠ ONESHOT_CONTROLLING_TIP
PROMOTE=0
T08_SEALED_IMMUTABLE=1
```

Oneshot controlling EXT SHA authority: `FULL_FEATURE_ONESHOT_001\EXTENSIONHOST_GATE.md` (EA5D / later tips). Do not re-claim 8D8999CD as product controlling.
