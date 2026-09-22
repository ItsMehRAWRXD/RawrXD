Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 3: items 31–35
======================================================================

This batch attacks two things that Batch 2 exposes:
  (1) proposal acceptance rate
  (2) verification overhead outside the full Q4_K target pass

31  Shallow self-speculative drafter
    - no second model dependency
    - proposal[0] is exact current target argmax
    - later proposals use first D layers of the SAME Qwen32 model
    - draft KV always rolls back before target verification

32  Adaptive draft controller
    - acceptance EWMA
    - dynamically adjusts window 2/3/4 and shallow draft depth 16/12/8
    - n-gram proposal only wins when it agrees with exact first target token

33  Persistent speculative workspace
    - removes per-window vectors
    - removes per-head attention score allocations
    - buffers grow only with model/context geometry

34  Dual-GPU LM-head top1 shader
    - computes local argmax on each GPU
    - returns only 2*(value,index)*batch rather than 4*vocab F32 logits
    - exact host merge with first-index tie break

35  Bind GPU top1 into verifier + authority v2
    - final 85 TPS PASS additionally requires real draft windows and GPU-top1
    - greedy speculative output must still equal ordinary target output exactly

Apply after 85TPS Batches 1-2:
  Expand-Archive "$HOME\Downloads\deep2_qwen32_85tps_batch3.zip" `
    "F:\~dev\qwen32_85tps_batch3" -Force

  Get-ChildItem "F:\~dev\qwen32_85tps_batch3\*.patch" |
    Sort-Object Name |
    ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
    }

Rebuild shaders:
  & "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

Build:
  cmake --build "F:\~dev\build_p2" --config Release --target qwen32_85tps_gate

Run:
  $env:DEEP2_GPU0_THROUGHPUT_WEIGHT="1.00"
  $env:DEEP2_GPU1_THROUGHPUT_WEIGHT="1.00"
  $env:DEEP2_ROW_SPLIT_AUTO="1"
  $env:DEEP2_SELF_DRAFT_LAYERS="8"

  & "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
    "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 128

Authority remains fail-closed:
  SPEC_GREEDY_PARITY=PASS
  GPU_DEVICES=2
  STRICT_VIOLATION=0
  UNPLANNED_FALLBACKS=0
  SELF_DRAFT_WINDOWS+NGRAM_DRAFT_WINDOWS > 0
  GPU_TOP1_BATCHES > 0
  VERIFIED_PER_TARGET_PASS > 1
  DECODE_TPS_REAL_VERIFIED >= 85.0
  DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

If HOLD remains, keep the receipt. Batch 4 should then move the speculative
attention/FFN activation chain on-device and switch wDown / O projection to
column-split partial reductions so intermediate activations no longer round-trip
through host memory between heavy matrices.
