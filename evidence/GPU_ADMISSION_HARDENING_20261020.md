# GPU admission and recovery hardening — 2026-10-20

## Implementation

`rawr run` GPU admission now uses the explicit `gpu_config.json` binding for the R9700 primary and RX 7800 XT secondary. Both `tools/rawrxd_parity_final/activate.ps1` and `tools/rawrxd_finishers/rawr_run_dropin/activate.ps1` now:

- check the configured secondary before launch and again after the task exits;
- recognize Device Manager codes 22 (disabled), 31 (driver start failure), and 43 (Windows stopped the device);
- detect a configured adapter that is missing from WMI or missing from Vulkan enumeration;
- perform at most one targeted `pnputil /restart-device`/`enable-device` attempt per invocation;
- refuse disruptive recovery while Deep2, `rawr_run`, Python benchmark, or Ollama processes are active;
- protect the configured R9700 primary from all reset operations;
- emit `evidence/gpu_recovery_telemetry.json` and fail closed when admission cannot be established.

A post-run check preserves the model runner's exit code while surfacing an unrecovered GPU warning.

## Verification

- PowerShell AST parse: parity final `0` errors; finisher drop-in `0` errors.
- `gpu_config.json`: valid JSON; one explicit primary and one explicit secondary.
- Reset-disabled smoke: returned `recovery_result=skipped` without touching devices.

## Hardware witness

An elevated targeted disable/enable was executed for the RX 7800 XT at 2026-10-20 16:45 EDT. Disable and enable commands both returned success, but CIM/PnP still reported `CM_PROB_FAILED_POST_START` / Code 43 afterward. Vulkan continued to list only the R9700 and integrated adapter. This is a genuine driver/PCIe/power initialization failure; no inference benchmark was launched.

Raw elevated log: `evidence/RX7800XT_RESET_20261020.log`.
- Runtime admission smoke with the configured IDs detected the live RX 7800 XT Code 43 and returned `recovery_result=blocked_active_inference`, `admission_result=denied_recovery_failed` while Ollama was active; no disruptive reset was attempted.
