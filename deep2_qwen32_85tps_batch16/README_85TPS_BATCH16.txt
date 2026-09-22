Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 16: items 96–100
======================================================================

Basis
-----
Batch 15 already introduced pre-recorded QKV/Gate-Up command groups, GPU
speculative prefix acceptance, resident verified-hidden handoff, and coarse
timeline layer chaining.

Batch 16 attacks the host synchronization still left around those paths.
It does NOT claim 85 TPS. The only authority remains the measured gate.

96  Nonblocking pre-recorded groups
    - DEEP2_RECORDED_GROUP_ASYNC=1
    - when timeline semaphores are live, pre-recorded QKV/Gate-Up groups submit
      without the old post-submit vkWaitForFences()
    - old synchronous path remains fallback
    - exposes async-submit vs sync-wait counters

97  Device-resident speculative acceptance
    - new RunSpecAcceptPrefixResident()
    - consumes target/proposal ID buffers already resident on GPU
    - removes the two host->GPU ID uploads
    - only 3 uint32 result words return to host

98  Timeline verified-hidden handoff
    - hidden capture/restore can be submitted as timeline dependencies
    - no immediate endSubmitWait boundary
    - explicit ticket wait owns transient command-buffer lifetime

99  Real speculative-window amortization counters
    - DEEP2_SPEC_WINDOW_CAP=1..4, default 4
    - counts prepared proposal tokens
    - counts target verification windows
    - counts accepted verified output tokens
    - makes verified tokens per target window visible to authority

100 Authority v15
    New live-path requirements:
      RECORDED_GROUP_WAITFREE=PASS
      SPEC_ACCEPT_RESIDENT=PASS
      HIDDEN_TIMELINE_HANDOFF=PASS
      REAL_WINDOW_AMORTIZATION=PASS

    Older gates remain mandatory:
      SPEC_GREEDY_PARITY=PASS
      GPU1_DEVICE_READY=1
      UNPLANNED_FALLBACKS=0
      ZERO_MEASURED_WEIGHT_UPLOADS=PASS
      HOST_TRAFFIC_BOUNDED=PASS
      Q4K_AUTOTUNE=PASS
      ASYNC_DUAL_GPU_PATH=PASS
      THREE_STAGE_SPEC_PIPELINE=PASS
      RECORDED_GROUP_HOTPATH=PASS
      GPU_ACCEPT_PREFIX=PASS
      RESIDENT_HIDDEN_HANDOFF=PASS
      LAYER_TIMELINE_CHAIN=PASS

    Performance authority remains:
      STEADY_RUN0_TPS>=85
      STEADY_RUN1_TPS>=85
      STEADY_RUN2_TPS>=85

      DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

Important integration note
--------------------------
These patches are based on the Batch-15 source surface in the pasted thread,
not the live F:\~dev checkout. They are intentionally fail-closed, but local
source drift can require a small 3-way/manual merge. They have not been
compiled or benchmarked here.

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch16.zip" `
  "F:\~dev\qwen32_85tps_batch16" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch16\*.patch" |
  Sort-Object Name |
  ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
  }

Build
-----
& "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

cmake --build "F:\~dev\build_p2" `
  --config Release `
  --target qwen32_85tps_gate

Run
---
$env:DEEP2_ROW_SPLIT_AUTO="1"
$env:DEEP2_COLUMN_SPLIT_AUTO="1"
$env:DEEP2_ASYNC_SPLIT_CONTROL="1"
$env:DEEP2_Q4K_AUTOTUNE="1"
$env:DEEP2_SELF_DRAFT_LAYERS="8"

$env:DEEP2_RECORDED_GROUP_ASYNC="1"
$env:DEEP2_SPEC_WINDOW_CAP="4"

& "F:\~dev\build_p2\Release\qwen32_85tps_gate.exe" `
  "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" `
  256

Expected new receipt surface
----------------------------
GPU0_RECORDED_GROUP_ASYNC_DELTA>0
GPU1_RECORDED_GROUP_ASYNC_DELTA>0
GPU0_RECORDED_GROUP_SYNC_WAITS_DELTA=0
GPU1_RECORDED_GROUP_SYNC_WAITS_DELTA=0
SPEC_ACCEPT_RESIDENT_OPS_DELTA>0
SPEC_ACCEPT_INPUT_UPLOAD_BYTES_DELTA=0
HIDDEN_TIMELINE_SUBMITS_DELTA>0

SPEC_VERIFIED_TARGET_WINDOWS>0
SPEC_ACCEPTED_VERIFIED_TOKENS>SPEC_VERIFIED_TARGET_WINDOWS

RECORDED_GROUP_WAITFREE=PASS
SPEC_ACCEPT_RESIDENT=PASS
HIDDEN_TIMELINE_HANDOFF=PASS
REAL_WINDOW_AMORTIZATION=PASS

And still:
STEADY_RUN0_TPS>=85
STEADY_RUN1_TPS>=85
STEADY_RUN2_TPS>=85
DEEP2_QWEN25_32B_REAL_85TPS_001=PASS
