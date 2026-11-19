# Vulkan device enumeration

Retained logs enumerate both discrete AMD devices:

- Ordinal 0: AMD Radeon AI PRO R9700, device `0x7551`, compute capable,
  approximately `31.86 GB` local memory.
- Ordinal 2: AMD Radeon RX 7800 XT, device `0x747E`, compute capable,
  approximately `15.98 GB` local memory.
- Direct3D12 fallback duplicates were identified and deduplicated.

The retained execution selected the R9700. A same-SHA run explicitly binding
and executing on the RX 7800 XT, followed by a dual-device run, is not retained.

`S053=ENUMERATION_PASS_BINDING_MATRIX_OPEN`
`RX7800XT_RUNTIME_BINDING=OPEN`
`DUAL_GPU_BINDING=OPEN`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`
