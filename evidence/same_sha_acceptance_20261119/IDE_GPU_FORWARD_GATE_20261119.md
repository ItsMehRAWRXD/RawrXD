# Serverless IDE GPU-forward gate

## Identity

```ini
SOURCE_SHA=UNCOMMITTED_WORKTREE_BASELINE
EXECUTABLE=F:\\rawrxd\\build\\bin\\Release\\RawrXD-Win32IDE-Native.exe
EXECUTABLE_SHA256=B39ED195BB4924D73E76E83DD2C461F778E4BD04499D817ED4D96EC1096B62FD
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
HTTP_SERVER=NOT_USED
```

## Command

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File evidence/same_sha_acceptance_20261119/ide_deep2_probe.ps1 -Model F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf -TimeoutSec 45
```

## Observed result

The native GUI loaded the model and generated a non-empty response (`gen=1`, `gen_len=31`, process remained healthy until probe cleanup). The corrected telemetry now reports the actual execution state:

```text
Backend: Deep2Engine (Vulkan initialized; CPU forward)
GPU Dispatches: 0
CPU Fallbacks: 0
GPU Forward Real: 0
GPU Forward Q4K Ops: 0
GPU Forward Q6K Ops: 0
GPU Forward Fallbacks: 0
GPU Devices: 2
```

## Disposition

```ini
SERVERLESS_IDE_CHAT=PASS
GPU_FORWARD_IN_IDE=NOT_REACHED_OR_NOT_COMMITTED
TELEMETRY_ACCURACY=PASS
STRICT_REFERENCE_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```

This receipt deliberately does not classify the GUI generation as GPU inference. Vulkan initialization alone is insufficient evidence of resident GPU execution.
