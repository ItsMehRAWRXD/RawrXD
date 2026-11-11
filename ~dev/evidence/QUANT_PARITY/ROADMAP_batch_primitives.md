# Runtime roadmap — 15-primitive catalogs (recorded 2026-09-18)

Status: DESIGN SKETCHES ONLY. They reference runtime types (Tensor, Gpu,
KVPage, KVArena, StreamSession, CommandGraph, DecodeState, DecodeTxn,
WeightPage, Expert, StageBuffer/Slot, TokenRing, GpuStats, DescriptorCache,
ScratchArena/Pools) that DO NOT EXIST in the tree yet. Not droppable code.
Adopt one-by-one as the Deep2 runtime layers they belong to get built.

Priority order (from review):
  01 ZERO_HOST_MATERIALIZE_DECODE   (attack ~6,401-materialization envelope)
  02 RESIDENT_WEIGHT_RANGE_EXEC
  03 TRIPLE_BUFFER_GPU_HANDOFF
  04 NEXT_LAYER_PREFETCH
  05 PERSISTENT_VK_EXEC_GRAPH
  06 ASYMMETRIC_DUAL_GPU_SCHEDULER
  07 BELADY_WEIGHT_PAGER
  08 HOT_WEIGHT_LOCK
  09 PAGED_KV_ARENA
  10 KV_INT8_FP16_TIER
  11 LOAD_TIME_NATIVE_REPACK
  12 FUSED_TRANSFORMER_SUPERKERNELS
  13 PERSISTENT_STREAM_SESSION
  14 LOCK_FREE_TOKEN_RING
  15 DECODE_EPOCH_ROLLBACK

Theme groups:
- Capacity: VRAM budget admission, hot/cold classification, next-use (Belady)
  eviction, paged KV alloc, cold KV compression, layer windows, pin budgets.
- TPS: zero-host intermediates, async layer prefetch, triple-buffer staging,
  dynamic dual-GPU split by EMA throughput, persistent command reuse,
  native-layout repack-once, fused block dispatch, descriptor caches,
  EMA kernel/queue latency, barrier elision, scratch reuse.
- Streaming/stability: persistent model session, SPSC token ring
  (push/pop/backpressure/sequence), heartbeat + progress touch, fail-closed
  token validation, decode transaction mark/rollback, in-flight residency
  guard, generation-epoch cancel, memory-pressure guard, warm session
  reuse/recovery, KV page recycle/hot promotion.

Catalogued snippets live in the conversation history (batches labeled
BATCH_1..BATCH_8 with CAPACITY/TPS/STREAM/STABILITY themes). Recreate each
primitive at adoption time against the actual Deep2 classes; several
variants across batches express the same idea (e.g. eviction score =
nextUse-distance × bytes, optionally reuse-weighted or hot-zeroed).