Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 6: items 46–50
======================================================================

This batch continues past the original closure batch because no Batch-5
measurement receipt was supplied with this request. It attacks the next
structural costs without weakening the authority gate.

46  Resident speculative activation arena
    hidden/norm/Q/K/V/attention/O/gate/up/act/down all have persistent
    device buffers sized for the 1..4-token verification window.

47  Device-resident non-weight layer chain
    reusable batch RMSNorm/SwiGLU/residual operations operate directly on
    the resident speculative arena.

48  Primary-GPU partial reduction bridge
    for dual-GPU column split:
      GPU0 owns the continuing activation.
      GPU1's partial alone crosses persistent mapped host staging.
      GPU0 reduces that partial on-device.
    Does not depend on Vulkan peer/external-memory support.

49  Pipeline timing / bounded proposal overlap counters
    records:
      proposal_ns
      verify_ns
      target_batch_ns
      pipeline_windows
    Draft work never becomes authoritative and never races target KV writes.

50  85-TPS authority v5
    32-token warmup remains outside measurement.
    THREE long runs are measured.
    Reports min + median.
    ALL THREE runs must independently reach >=85 verified output TPS.

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch6.zip" `
  "F:\~dev\qwen32_85tps_batch6" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch6\*.patch" |
  Sort-Object Name |
  ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
  }

Shader build
------------
& "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

Build
-----
cmake --build "F:\~dev\build_p2" `
  --config Release `
  --target qwen32_85tps_gate

Run
---
$env:DEEP2_GPU0_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_GPU1_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_ROW_SPLIT_AUTO="1"
$env:DEEP2_COLUMN_SPLIT_AUTO="1"
$env:DEEP2_SELF_DRAFT_LAYERS="8"

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 256

Authority remains fail-closed
-----------------------------
SPEC_GREEDY_PARITY=PASS
GPU_DEVICES>=2
GPU1_DEVICE_READY=1
STRICT_VIOLATION=0
UNPLANNED_FALLBACKS=0

GPU_TOP1_BATCHES>0
GPU_BATCH_NORM_OPS>0
GPU_BATCH_SWIGLU_OPS>0
GPU_BATCH_ATTENTION_OPS>0
DUAL_COLUMN_SPLIT_OPS>0
KV_MIRROR_RESIDENT_ATTN>0
VERIFIED_PER_TARGET_PASS>1.0
PIPELINE_WINDOWS>0
TARGET_BATCH_NS>0

STEADY_RUN0_TPS>=85.0
STEADY_RUN1_TPS>=85.0
STEADY_RUN2_TPS>=85.0

DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

Important
---------
If the RX 7800 XT still fails vkCreateDevice, expect GPU1_DEVICE_READY=0 and
HOLD. This source drop cannot turn a device-creation failure into dual-GPU
throughput evidence.

These patches are source drops derived against the inspected tree + prior
cumulative batches; they have not been compiled on the user's local checkout.
Compile errors or patch conflicts should be fixed minimally without reopening
the already-closed Qwen transformer parity gate.
