# RawrXD GPU Code 31 PnP Recovery Receipt

## Provenance

```ini
RECEIPT_ID=GPU_CODE31_PNP_20261028
SOURCE_ROOT=F:\rawrxd
BRANCH=fix/deep2-multimodel-safety-20261025
SOURCE_COMMIT=282f13fdcedcde20d8ce2c5531bd9cf444475a32
PROMOTE=0
```

The source commit adds explicit Code 31 recognition, fail-closed device
exclusion, opt-in reset policy, elevation reporting, and a dedicated PnP
probe. It does not claim that a disabled device was recovered.

## Product authority lock

The frozen product executable was not rebuilt or modified by this work.

```ini
PRODUCT_EXE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe
PRODUCT_SHA256=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
PRODUCT_TIP_FROZEN=1
GHOSTTEXT_SCOPE=WITNESS_ONLY
```

## Build

```ini
TARGET=deep2_gpu_code31_pnp_probe
BUILD_DIR=F:\rawrxd\build_ide
BUILD_COMMAND=VsDevCmd.bat -arch=amd64 -host_arch=amd64 && cmake --build F:\rawrxd\build_ide --target deep2_gpu_code31_pnp_probe --parallel 8
BUILD_EXIT=0
PROBE_EXE=F:\rawrxd\build_ide\deep2_gpu_code31_pnp_probe.exe
PROBE_SHA256=617E58125635A4B9AD4D65194DCE68F4050BF08C42C7F8A716ACA11F35D6B084
```

## Runtime witnesses

Hardware observed three AMD devices. The AMD Radeon RX 7800 XT reported
`PROBLEM_CODE=31`, was marked unhealthy and excluded, and was not selected as
the compute device. The AMD Radeon AI PRO R9700 remained the compute primary.

### No reset opt-in

Evidence: `no_optin_v2.txt`

```ini
EXIT=0
PROBLEM_31=1
RESET_ATTEMPTED=0
RESET_OK=0
RESET_SKIPPED=1
RESET_REQUIRES_ELEVATION=0
ACCESS_DENIED=0
HEALTHY=0
RECOGNIZE=PASS
RESET_DISPOSITION=RESET_SKIPPED_OPT_IN_REQUIRED
RAW_SHA256=14C6CD0571C03E39C5398C2C2CAAA0F51585FF6C3779A48BBB22BE2523A400F5
```

### Reset opt-in from unelevated process

Evidence: `optin_unelevated_v2.txt`

```ini
EXIT=0
PROBLEM_31=1
RESET_ATTEMPTED=0
RESET_OK=0
RESET_SKIPPED=1
RESET_REQUIRES_ELEVATION=1
ACCESS_DENIED=1
HEALTHY=0
RECOGNIZE=PASS
RESET_DISPOSITION=RESET_BLOCKED_REQUIRES_ELEVATION
RAW_SHA256=CBCA361050B23FB7A36DD176BCB8F398E9270E1A81EDC8E48B1454E29B019BC1
```

These results prove recognition and safe admission behavior. They do not prove
privileged reset success; no elevated reset was attempted in this receipt.

## Tests

```ini
CTEST_FILTER=deep2_gpu_code31_pnp_probe|workspace_path_policy_smoke|native_tool_protocol_smoke|cursor_parity_registry_smoke
CTEST_PASSED=4
CTEST_FAILED=0
CTEST_EXIT=0

VULKAN_SMOKE_EXE=F:\rawrxd\build_ide\deep2_gpu_code31_reset_smoke.exe
VULKAN_SMOKE_EXIT=0
VULKAN_SMOKE_RESULT=PASS
VULKAN_CODE31_MAPPING=PASS
VULKAN_RESET_FAIL_CLOSED=PASS
```

## Disposition

```ini
CODE31_RECOGNITION=PASS
CODE31_DEVICE_EXCLUSION=PASS
UNELEVATED_RESET_GATING=PASS
ACTUAL_HARDWARE_RESET=NOT_RUN
GPU_RESET_CERTIFIED=NOT_CERTIFIED
DEEP2_GPU_INFERENCE=NOT_CERTIFIED
PROMOTE=0
```
