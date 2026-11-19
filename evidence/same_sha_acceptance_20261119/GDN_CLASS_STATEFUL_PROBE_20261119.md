# Stateful production Vulkan GDN probe

## Identity

- Source SHA: `e3e0531ed7d361799c746e71b9c0ffd2b34e7dc4`
- Executable SHA-256: `ACD363E4A951F762375E78741D80310DDCDE01C4D9B3BB112C5802F4E2C43D96`
- Device: AMD Radeon AI PRO R9700

## Command

```powershell
cmake --build F:\rawrxd\build --target deep2_vulkan_gdn_dispatch_probe --config Release -- /m:1
F:\rawrxd\build\bin\Release\deep2_vulkan_gdn_dispatch_probe.exe
```

Exit: `0`.

## Observed output

```text
GDN_CLASS_PIPELINE=READY
GDN_CLASS_FIRST_PARITY=PASS max_abs=8.9407e-08
GDN_CLASS_STATE_CONTINUITY=PASS max_abs=1.19209e-07
GDN_CLASS_RESET_CONTINUITY=PASS max_abs=8.9407e-08
GDN_CLASS_RESET_INDEPENDENT=PASS
GDN_CLASS_DISPATCHES=3
GDN_CLASS_RESULT=PASS
```

This verifies the production `VulkanCompute` state map, repeated dispatches, state continuity, reset behavior, and independent reset behavior. It is still an operator/stateful probe, not full-model Qwen4Exp certification.

```ini
GDN_CLASS_STATEFUL_GPU=PASS
GDN_DISPATCHES=3
GDN_CPU_FALLBACKS=0
GDN_STATE_RESET=PASS
QWEN4EXP_FULL_MODEL=NOT_CERTIFIED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
