# Topology-agnostic device layer (2026-09-06)

## Principle

`STREAMER_GPU_SOLO_001` is the first certified instance of the generic **SingleGpu**
execution path — not an R9700-specific architecture.

```text
Deep2Engine
   │
   ▼
Deep2DeviceManager
   ├─ enumerate adapters (DXGI)
   ├─ score by VRAM/capability (MASM Deep2Device_Score)
   ├─ apply RAWRXD_GPU_POLICY / RAWRXD_GPU_DEVICES / DEEP2_GPU_SELECT
   └─ pick primary (MASM Deep2Device_PickBestIndex)
           │
           ▼
VulkanCompute::InitializeSolo(primary_name)
   → one VkPhysicalDevice
   → one VkDevice
```

## Policy (user first-class)

```text
RAWRXD_GPU_POLICY=AUTO          # default: best discrete by score
RAWRXD_GPU_DEVICES=CPU          # force CPU_NATIVE
RAWRXD_GPU_DEVICES=0            # open adapter index 0 only
RAWRXD_GPU_DEVICES=ALL          # (solo gate still opens best one)
DEEP2_GPU_SELECT=<name|stable>  # name / identity substring override
```

Stable identity (not adapter index):

```text
VENDOR:DEVICEID:LUID
e.g. 1002:XXXX:................
```

## Witnesses (generic)

```text
DEEP2_DEVICE_COUNT_DETECTED=N
DEEP2_DEVICE_COUNT_OPENED=1
DEEP2_DEVICE_i_NAME=...
DEEP2_DEVICE_i_VENDOR=AMD|NVIDIA|INTEL|OTHER
DEEP2_DEVICE_i_STABLE_ID=...
DEEP2_DEVICE_i_DUTY=COMPUTE_PRIMARY|DETECTED/UNUSED
DEEP2_PRIMARY_INDEX=...
DEEP2_EXEC_PATH=SINGLE_GPU
```

## Gate order unchanged

```text
CPU_NATIVE CERTIFIED
  → STREAMER_GPU_SOLO_001   SingleGpu (this machine: largest discrete)
  → STREAMER_GPU_SOLO_002   same path, second discrete as primary via policy
  → STREAMER_SPECULATIVE_001
  → STREAMER_MULTIGPU_001
  → STREAMER_AUTOTUNE_001
```
