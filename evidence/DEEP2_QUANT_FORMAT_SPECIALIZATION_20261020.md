# Deep2 quant GEMV format specialization

## Result

The row4 and row8 packed GEMV shader sources now accept `DEEP2_SPECIALIZED_KIND`
at compile time.  The build produces one SPIR-V module for each supported
packed format (Q4_K, Q6_K, Q2_K, Q3_K, and Q5_K), and CMake fails immediately
when `glslc` fails or does not produce an output artifact.

The generated row8 artifacts were compared with the prior runtime-dispatch
module using `spirv-dis`:

| module | bytes | `OpBranchConditional` |
|---|---:|---:|
| runtime-dispatch row8 | 32,224 | 65 |
| Q2_K specialized | 7,384 | 16 |
| Q3_K specialized | 9,484 | 15 |
| Q4_K specialized | 7,920 | 18 |
| Q5_K specialized | 10,088 | 16 |
| Q6_K specialized | 6,516 | 13 |

This is compile-time dead-path elimination evidence, not a throughput claim.
The existing Vulkan selector still uses the established runtime pipeline until
the per-kind pipeline cache is wired and parity-tested.  No certification or
100+ TPS claim is made by this artifact alone.

## Reproduction

```powershell
cmake --build build --config Release --target deep2_quant_specialized_shaders -- /m:1
```

The command completed successfully on 2026-10-20.  The source generator is
also available as `tools/shaders/build_quant_specialized.ps1`; it stops on the
first compiler error and does not mask `glslc` stderr or exit status.
