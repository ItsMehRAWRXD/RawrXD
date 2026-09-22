Deep2 Qwen2.5-Coder-32B — 85 REAL TPS campaign
Batch 9: items 61–65
======================================================================

No Batch-8 measured receipt accompanied this request. Batch 9 removes another
generic materialization boundary without weakening the authority gate.

61  Primary resident full-output assembly
    - GPU0 owns the complete batch output buffer
    - GPU0 row slice is copied directly into its final row offsets
    - no CPU full-vector concatenation

62  Secondary row-slice direct offset import
    - only GPU1's missing rows cross mapped host staging
    - imported directly into GPU0's full-output offsets
    - no peer-memory assumption

63  Resident output -> next-group boundary
    - one bounded full activation materialization at a GROUP boundary when
      peer copy is unavailable
    - replaces per-matrix host materializations
    - exact byte counter added

64  Fused primary speculative layer submit
    - one primary fused recording for cheap device math around dependent GEMVs
    - RMSNorm / attention / residual / FFN activation chain shares a submit
      envelope where dependency boundaries permit

65  Authority v8 host-byte budget
    - retains every previous correctness/performance gate
    - requires resident full-output assembly
    - requires fused speculative layer-graph activity
    - records secondary-import + group-boundary host bytes / verified token
    - generous <64 MiB / verified-token regression ceiling
    - still requires all 3 steady runs >=85 TPS

Apply
-----
Expand-Archive `
  "$HOME\Downloads\deep2_qwen32_85tps_batch9.zip" `
  "F:\~dev\qwen32_85tps_batch9" -Force

Get-ChildItem "F:\~dev\qwen32_85tps_batch9\*.patch" |
  Sort-Object Name |
  ForEach-Object {
      git -C "F:\~dev" apply --3way $_.FullName
      if ($LASTEXITCODE -ne 0) { throw "FAILED: $($_.Name)" }
  }

Rebuild
-------
& "F:\~dev\rawrxd\src\deep2\build_batch9_shaders.ps1"

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
All prior gates remain required, especially:

  SPEC_GREEDY_PARITY=PASS
  GPU1_DEVICE_READY=1
  UNPLANNED_FALLBACKS=0
  ZERO_MEASURED_WEIGHT_UPLOADS=PASS

  RESIDENT_FULL_OUTPUT_COPIES_DELTA>0
  SPEC_LAYER_GRAPH_SUBMITS_DELTA>0
  HOST_TRAFFIC_BOUNDED=PASS

  STEADY_RUN0_TPS>=85
  STEADY_RUN1_TPS>=85
  STEADY_RUN2_TPS>=85

  DEEP2_QWEN25_32B_REAL_85TPS_001=PASS

This ZIP is a source drop derived against the inspected tree and cumulative
prior batches. It has not been compiled on the user's local checkout. Applying
it is not an 85-TPS receipt.
