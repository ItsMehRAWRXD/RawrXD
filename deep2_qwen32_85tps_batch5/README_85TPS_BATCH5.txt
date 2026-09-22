Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 5: items 41–45 — closure batch
======================================================================

41  Persistent device speculative KV mirror
    - per-layer GPU K/V storage
    - [kvHead][maxSeq][headDim]
    - supports range/delta upload
    - resident attention reads mirror directly

42  Committed-prefix KV binding
    - uploads only committed positions absent from the device mirror
    - speculative K/V tail is overwritten in-place
    - only accepted target prefix advances mirror-commit bookkeeping
    - rejected tail is never treated as committed

43  Adaptive Q4_K column split
    - measures completion time on each GPU
    - EWMA learns actual partial columns/sec
    - future O/wDown split follows real device throughput
    - always retains Q4_K 256-column block alignment

44  Grouped QKV + Gate/Up batch execution
    - one input upload per GPU for Q/K/V group
    - one input upload per GPU for Gate/Up group
    - one fused submit per group per GPU
    - removes 3x/2x duplicate normalized-activation uploads

45  Steady-state 85-TPS authority v4
    - 32-token warmup excluded from measurement
    - TWO independent long runs
    - default 256 verified tokens/run
    - minimum supported authority run = 128 tokens
    - both runs must independently exceed 85 verified output TPS
    - GPU1_DEVICE_READY must be 1
    - persistent device-KV counters must be nonzero

Apply after 85TPS Batches 1–4
-----------------------------
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch5.zip" `
  "F:\~dev\qwen32_85tps_batch5" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch5\*.patch" |
  Sort-Object Name |
  ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
  }

Rebuild shader set
------------------
& "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

Build
-----
cmake --build "F:\~dev\build_p2" `
  --config Release `
  --target qwen32_85tps_gate

Run final default 256-token x2 authority
----------------------------------------
$env:DEEP2_GPU0_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_GPU1_THROUGHPUT_WEIGHT="1.00"
$env:DEEP2_ROW_SPLIT_AUTO="1"
$env:DEEP2_COLUMN_SPLIT_AUTO="1"
$env:DEEP2_SELF_DRAFT_LAYERS="8"

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" 256

Closure law
-----------
SPEC_GREEDY_PARITY=PASS
GPU_DEVICES>=2
GPU1_DEVICE_READY=1
STRICT_VIOLATION=0
UNPLANNED_FALLBACKS=0

SELF_DRAFT_WINDOWS+NGRAM_DRAFT_WINDOWS > 0
GPU_TOP1_BATCHES > 0
GPU_BATCH_NORM_OPS > 0
GPU_BATCH_SWIGLU_OPS > 0
GPU_BATCH_ATTENTION_OPS > 0
DUAL_COLUMN_SPLIT_OPS > 0
KV_MIRROR_RESIDENT_ATTN > 0
VERIFIED_PER_TARGET_PASS > 1.0

STEADY_RUN0_TPS >= 85.0
STEADY_RUN1_TPS >= 85.0

DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

Important hardware blocker classification
-----------------------------------------
If the RX 7800 XT still fails vkCreateDevice, expect:

  GPU1_DEVICE_READY=0
  DEEP2_QWEN25_32B_REAL_85TPS_001=HOLD

That is a device/driver-state blocker, not permission to claim a one-GPU
85-TPS result.

If both GPUs create successfully but throughput remains below 85, retain HOLD.
The receipt then tells us whether the remaining limiter is:
  - acceptance rate,
  - target-pass bandwidth,
  - attention/KV traffic,
  - or inter-device/host synchronization.

Applying source is not an 85-TPS receipt. Only the measured two-run gate is.
