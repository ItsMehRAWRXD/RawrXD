Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 2: items 26–30
======================================================================

Purpose
-------
This batch connects the speculative roofline work to the real transformer.

26  Exact 1..4 token batch embedding / linear / final-logit APIs.
27  Simultaneous dual-GPU Q4_K batch target pass.
28  Exact causal speculative block forward across all 64 dense Qwen layers.
29  Exact greedy longest-prefix accept/reject with transactional KV.
30  Wire verified speculation into generate() + real 85-TPS authority gate.

Correctness law
---------------
A draft token is NEVER emitted because the drafter predicted it.

For proposals d0..d3:

  target(current_hidden) must equal d0

then the real Qwen2.5-32B target batch-forwards d0..d3. For every next
candidate, its predecessor's full target logits must have argmax == candidate.

At first mismatch:
  - accepted exact prefix is committed to KV
  - speculative tail is rewound
  - real target argmax is emitted

If all proposals match:
  - all proposal KV positions commit
  - one real target bonus token is emitted

Therefore speculative greedy output must be token-for-token identical to
ordinary greedy target decode.

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch2.zip" `
  "F:\~dev\qwen32_85tps_batch2" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch2\*.patch" |
  Sort-Object Name |
  ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
  }

Shaders
-------
& "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

Build
-----
cmake -S "F:\~dev" -B "F:\~dev\build_p2" `
  -G "Visual Studio 17 2022" -A x64

cmake --build "F:\~dev\build_p2" `
  --config Release `
  --target qwen32_85tps_gate

Run
---
$env:DEEP2_GPU0_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_GPU1_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_ROW_SPLIT_AUTO="1"

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" `
  128

Final PASS is still fail-closed
-------------------------------
SPEC_GREEDY_PARITY=PASS
GPU_DEVICES=2
STRICT_VIOLATION=0
UNPLANNED_FALLBACKS=0
VERIFIED_PER_TARGET_PASS>1
DECODE_TPS_REAL_VERIFIED>=85.0
DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

If the n-gram drafter has low acceptance, the engine remains exact but will
not reach 85. Do NOT weaken the gate. The next batch should improve proposal
quality (self-speculative / draft-model lane) and move block attention +
activation functions fully onto GPU.
