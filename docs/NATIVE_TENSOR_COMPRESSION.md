# Native GGUF tensor compression

## Build

The standalone compressor has no external codec dependency:

```sh
c++ -std=c++17 -O2 tools/native_gguf_f16.cpp -o native_gguf_f16
```

The production `~dev/rawrxd` CMake project exposes the same executable as
`rawrxd-native-gguf-compress` (option `RAWRXD_BUILD_NATIVE_GGUF_COMPRESSOR`,
enabled by default).

## Use

```sh
native_gguf_f16 input.gguf output.gguf 0.02 auto
native_gguf_f16 input.gguf output-q2.gguf 0.10 q2_k
native_gguf_f16 input.gguf output-q3.gguf 0.05 q3_k
native_gguf_f16 input.gguf output-q4.gguf 0.02 q4_k
native_gguf_f16 input.gguf output-q5.gguf 0.01 q5_k
native_gguf_f16 input.gguf output-q6.gguf 0.001 q6_k
```

The tolerance is a maximum absolute reconstruction error in the source
tensor's value units. A format is accepted only when every block in the
whole tensor passes. `auto` tries Q2_K, Q3_K, Q4_K, Q5_K, then Q6_K in
increasing storage order; if no K format passes, the existing native
quantization/FP16 fallback selection continues. Manual format selection is
fail-closed: rejected tensors retain their original type and bytes.

Supported floating source types are F64, F32, F16, and BF16. The writer
preserves tensor names, dimensions, metadata, alignment, and untouched
tensor payloads. It writes standard GGUF type IDs and canonical block sizes:
Q2_K 84 B, Q3_K 110 B, Q4_K 144 B, Q5_K 176 B, Q6_K 210 B per 256 values.

## Deep2 and model loading

The production Deep2 `GGUFLoader` recognizes type IDs 10–14 and validates
their block geometry. `QuantKernelRegistry` has registered dequantization
and scalar GEMV paths for Q2_K through Q6_K; Q4_K also has its existing
specialized path. The integration test creates real GGUF files and loads
each K type through the mapped Deep2 loader.

## Verification gates

- The native block tests cover positive-only, negative-only, mixed-sign, and
  zero subgroups, plus strict-error rejection.
- The GGUF integration tests decode the written blocks independently and
  verify F64/F32/F16/BF16 source handling, automatic selection, and
  byte-for-byte fallback for non-finite or out-of-budget tensors.
- GitHub Actions compiles and runs the native tests on Linux and Windows.
  A queued workflow is not a passing result; record the completed run SHA
  and both platform conclusions before promotion.
- Model-level inference parity and VRAM/runtime benchmarks remain separate
  acceptance gates. File-size reduction alone is not evidence of inference
  parity.

## REAP boundary

This branch contains no REAP source/entrypoint to patch. The compressor emits
ordinary GGUF files with standard GGML type IDs, so a REAP workflow using the
Deep2 loader can consume the resulting file without a private container
format. A direct REAP invocation hook is not claimed until its owning source
is present and wired.
