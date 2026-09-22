Deep2 Qwen2.5-Coder-32B — 85 REAL OUTPUT TPS campaign
Batch 1: items 21–25
======================================================================

Why the architecture changes here
---------------------------------
The exact 18.49GB dense Q4 target cannot reach 85 tokens/s by doing one complete
target weight pass per emitted token on the user's current pair:

  R9700 physical peak GDDR6: 640 GB/s
  RX 7800 XT physical peak GDDR6: 624 GB/s
  aggregate raw peak: 1264 GB/s

  1264 / 18.49 = 68.36 dense target passes/s at impossible 100% efficiency.

At 80% memory efficiency:
  54.69 target passes/s
  85 / 54.69 = 1.554 verified output tokens required per target pass.

Therefore 85 REAL OUTPUT TPS must amortize weight reads across multiple verified
tokens. This batch starts an exact-target speculative path. Draft proposals are
never authoritative; the Qwen2.5-32B target must verify them.

Items
-----
21  Deep2Speculative roofline + authority accounting.
22  Replace empty MedusaDecoder stub with real no-dep history/prompt drafter.
23  KV speculative transaction / accepted-prefix rollback.
24  Q4_K 1..4-vector target-pass Vulkan shader + dispatch primitive.
25  85-TPS prerequisite gate. This may PASS; it does NOT mint 85 TPS.

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch1.zip" `
  "F:\~dev\qwen32_85tps_batch1" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch1\*.patch" |
  Sort-Object Name |
  ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
  }

Shader build
------------
& "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

Build prerequisite
------------------
cmake --build "F:\~dev\build_p2" `
  --config Release `
  --target qwen32_85tps_prereq

Run
---
& "F:\~dev\build_p2\Release\qwen32_85tps_prereq.exe"

Expected prerequisite receipt
-----------------------------
RAW_SINGLE_PASS_TPS=68.361...
EFF_SINGLE_PASS_TPS=54.689...
MIN_ACCEPTED_PER_PASS=1.554...
SPEC_WINDOW=4
KV_TRANSACTION=PASS
SINGLE_PASS_INSUFFICIENT=1
WINDOW_PHYSICALLY_SUFFICIENT=1
DEEP2_QWEN25_32B_85TPS_PREREQ_001=PASS

IMPORTANT
---------
This prerequisite PASS is NOT:
  DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

That final gate requires measured end-to-end verified output >=85.0 TPS with:
  exact Qwen2.5-32B target verification
  zero unverified draft tokens emitted
  zero CPU weight fallback
  deterministic greedy parity against ordinary target decode
  accepted-prefix KV correctness
  real dual-GPU Q4_K target arithmetic

Next batch (26–30)
------------------
Integrate block verification into Deep2Engine:
  26 batched token embeddings / hidden block
  27 QKV batch target verification
  28 causal in-window KV attention
  29 FFN batch verification
  30 exact greedy speculative accept/reject + end-to-end parity gate
