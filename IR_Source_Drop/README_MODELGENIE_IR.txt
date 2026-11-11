RAWRXD MODELGENIE NATIVE IR COMPLETION SOURCE DROP
================================================
Input frontier: 88b3d052bc, feat/hexmag-polymorphic-repeat-tuner-masm
Purpose: source patch and fail-closed local test runner, not a pass receipt.

1. Copy patch_modelgenie_ir.py and verify_ir_completion.ps1 into F:\rawrxd.
2. Preview the changes (no source writes):
   pwsh -NoProfile -File F:\rawrxd\verify_ir_completion.ps1
3. Inspect tmp_build\modelgenie_native_ir_validation\source.diff.
4. Apply the patch, compile, and run model verification:
   pwsh -NoProfile -File F:\rawrxd\verify_ir_completion.ps1 -Apply
5. To additionally commit/push ONLY after 300/300 and parity PASS:
   pwsh -NoProfile -File F:\rawrxd\verify_ir_completion.ps1 -Apply -Push
   (On an already patched source, the patch script intentionally fails closed.
    Run the compile/run commands and commit manually instead.)

Reference token ID: 1 (matches token0 baseline Forward(1)).
Expected model: 27 blocks, 2048 hidden, 102400 logits.
Required gates: 300 visited; 300 executed; 0 skipped; finite logits;
                predicted token 93633; PASS; exit code 0.

IMPORTANT:
- GitHub connector returned HTTP 403 on update_file: NO CHANGES WERE PUSHED.
- This patch has not compiled in the Windows environment and has not been
  executed against the 10.36 GB model. Token parity is NOT established.
- On partial failure, inspect the first incorrect tensor/operation and do not
  reclassify the run as PASS. The token-zero attention shortcut does not implement
  general multi-token attention/KV caching.
- Requires the existing generated headers, original ModelGenome files, MSVC,
  OpenMP/AVX-512 flags, and model/evidence paths already present locally.
- Large expert weights are dequantized per selected expert rather than
  caching entire 64-expert banks in RAM.
