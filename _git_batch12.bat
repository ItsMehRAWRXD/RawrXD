@echo off
cd /d F:\
git add ~dev/tests/qwen32_40tps_gate.cpp 2> nul
git commit -m "Batch 12 — Decode Throughput Breakdown Instrumentation

Instrument qwen32_40tps_gate.cpp with DEEP2_DECODE_THROUGHPUT_BREAKDOWN_001:
- 32-token warmup followed by 256-token measured run
- Wall-time capture via QueryPerformanceCounter (TOKEN_WALL_NS / AVG_TOKEN_WALL_NS)
- GPU compute: GPU0_COMPUTE_NS, GPU1_COMPUTE_NS, GPU_TIMED_NS
- Async waits: Q4K_ASYNC_WAIT_NS, DOWNLOAD_RING_WAIT_NS, EXPLICIT_WAIT_NS
- Residency: UPLOAD_DELTA, HIT_DELTA, TRANSFER_OVERLAP_NS
- Weight/data movement: Q4K_BATCH_WEIGHT_BYTES, SECONDARY_IMPORT_BYTES, FULL_OUTPUT_BOUNDARY_BYTES
- Timeline/queue: TIMELINE_SIGNALS, TIMELINE_WAITS, RECORDED_GROUP_SUBMITS, RECORDED_GROUP_SYNC_WAITS
- Host overhead: HOST_MERGE_OPS, HOST_MATERIALIZATIONS
- Explicit flags: ROW_EXECUTOR_WAIT_INSTRUMENTED=0, HOST_MERGE_NS_INSTRUMENTED=0
- ACCOUNTING_COMPLETE + TOKEN_WALL_ACCOUNTED_PCT" 2> nul
git push origin main 2> nul
git log origin/main -1 --oneline > f:\~dev\_git_remote_12.txt 2> nul
echo done > f:\~dev\_git_done_12.txt
