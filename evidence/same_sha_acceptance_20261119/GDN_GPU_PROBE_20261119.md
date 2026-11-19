# GDN Vulkan dispatch probe

## Scope

The `deep2_gdn_parity_harness` is reference-only and reports zero GPU dispatches by design. This receipt covers the existing real Vulkan operator probe, `deep2_qwen4exp_gdn_probe`.

## Identity

- Source SHA: `01ecf3558dc068ee2a6b0d72612b8d2cf151512d`
- Executable: `build/bin/Release/deep2_qwen4exp_gdn_probe.exe`
- Executable SHA-256: `F249F632D5A31E71588E6C19FB9336D66B9FDD5E1B9EA806A2AF75A4F77699A1`
- Shader: `src/deep2/shaders/deep2_qwen4exp_gdn.spv`
- Shader SHA-256: `9D276AFD7DF11FEF8EF1177AA937FCB1CD33AD611E88F527DC306E8AF3A3E506`
- Device: `AMD Radeon AI PRO R9700`, queue family `0`

## Test

```powershell
cmake --build F:\rawrxd\build --target deep2_qwen4exp_gdn_probe --config Release -- /m:1
F:\rawrxd\build\bin\Release\deep2_qwen4exp_gdn_probe.exe F:\rawrxd\src\deep2\shaders\deep2_qwen4exp_gdn.spv
```

Observed exit: `0`.

## Observed result

```text
GDN_GEOMETRY=PASS key_heads=16 value_heads=48 head_dim=128
GDN_PIPELINE=PASS
GDN_DISPATCHES=1 GDN_EXECUTION=PASS
GDN_OUTPUT_PARITY=PASS max_abs=1.67638e-08 max_rel=0.000377409 cosine=1
GDN_STATE_PARITY=PASS max_abs=1.16415e-10 max_rel=6.0254e-05 cosine=1
GDN_INDEPENDENT_PARITY=PASS
QWEN4EXP_FULL_MODEL=NOT_CERTIFIED
```

This certifies one real Vulkan GDN operator dispatch and CPU/reference parity for the synthetic probe. It does not certify full-model Qwen4Exp execution or the reference-only harness.

```ini
GDN_GPU_OPERATOR=PASS
GDN_GPU_DISPATCHES=1
GDN_CPU_FALLBACKS=0
GDN_OUTPUT_PARITY=PASS
GDN_STATE_PARITY=PASS
GDN_FULL_MODEL=NOT_CERTIFIED
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
