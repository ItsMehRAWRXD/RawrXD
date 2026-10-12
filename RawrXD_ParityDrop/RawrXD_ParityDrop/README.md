# RAWRXD_DEEP2_PACKED_DOT_AB_001 — source-only A/B parity drop

**Status:** Portable C++17 packed-dot self-test PASS on Linux. Not tested against the user's Windows GGUF or 20-/64-position llama.cpp reference. The current **Variant A remains the default and certified baseline**. Do not promote or report parity success until the measured run passes.

## What's included

- `src/modelgenie/RawrXDParityPackedDot.hpp` — header-only packed `Q4_K` and `Q6_K` matrix-vector kernels with ggml-style `Q8_K` activation quantization; no ggml import or DLL.
- `tools/apply_parity_packed_dot.py` — idempotent, fail-closed source integration into the shared `src/modelgenie/ModelGenieExecutor.cpp` and a safe attention diagnostic guard. Creates `.pre_parity_packed_dot_001.bak`.
- `tools/test_packed_dot.cpp` — portable math/layout regression test.
- `tools/run_parity_ab.ps1` — Windows baseline/packed teacher-forced A/B run.
- `tools/compare_parity.py` — exact-f32 full-logit scoring, logit margins, metrics, and a fail-closed promotion verdict, including real packed-kernel execution counters; Python standard library only.

## Install

Unzip the drop anywhere, then from its root:

```powershell
py -3 tools\apply_parity_packed_dot.py F:\rawrxd
```

Rebuild the existing `modelgenie_ir_executor.exe` and `RawrXDCore.dll` from source. No new libraries or build-system entries are required (the header is included from `ModelGenieExecutor.cpp`).

Optional isolated C++ test:

```powershell
cl /std:c++17 /EHsc /W4 /nologo /I src\modelgenie tools\test_packed_dot.cpp /Fe:packed_dot_test.exe
.\packed_dot_test.exe
```

On Unix for development only: `c++ -std=c++17 -O2 tools/test_packed_dot.cpp -o test_packed_dot && ./test_packed_dot`

## Compare with the existing immutable reference

Create a plain text `tokens_20.txt` containing the **same 20 full input token IDs** as the reference generation (the first 20 from the established 65-token sequence). `--teacher-forced` expects the input IDs, **not** the predicted output IDs.

```powershell
.\tools\run_parity_ab.ps1 `
  -Exe 'F:\rawrxd\tmp_build\modelgenie_ir_executor.exe' `
  -GGUF 'G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf' `
  -GenomeEvidence 'F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001' `
  -TokensFile '.\tokens_20.txt' `
  -ReferenceDir 'F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_teacher_forced' `
  -OutputRoot 'F:\rawrxd\evidence\RAWRXD_DEEP2_PACKED_DOT_AB_001' `
  -Count 20
```

Set `-Count 64` ONLY after 64 matching reference positions exist and provide exactly 64 input IDs. The script refuses insufficient data. Runtime A/B uses identical executable and model, toggling the packed-dot path using `RAWRXD_PARITY_PACKED_DOT=1`.

Potentially large: both runs write 409,600 bytes of logits per position, plus diagnostic captures. Only small metadata files (16 MiB or less) are cloned; if your ModelGenome requires a larger evidence asset, the fail-closed loader will report it and you must supply that input deliberately. Confirm free disk space.

## Acceptance / promotion

This is an **experimental numerical path**, not a forced token override. The runner writes a model/executable/token SHA-256 manifest and requires the packed-kernel counters to be nonzero. It is better only if real comparisons show (a) no argmax-match regression, (b) no regression in mean/min cosine or worst RMSE, and (c) an improvement in argmax count or mean cosine. The grader returns `PROMOTION_CANDIDATE` only then. The default production implementation remains Variant A until confirmed.

Packed operations follow reference *scalar* integer-dot grouping; AVX2/FMA hardware-specific ggml backends may still differ in floating-point rounding. None of these tests can certify 150 TPS or 671B operation.

To revert code safely:

```powershell
py -3 tools\apply_parity_packed_dot.py F:\rawrxd --revert
```

This will not alter `AttentionScoreScale()` or any A/B scale certificates.
