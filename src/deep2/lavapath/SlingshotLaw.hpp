#pragma once
/* From-scratch slingshot law — residency scheduler, not pinball quant. */
#define RAWRXD_SLINGSHOT_001 1
#define SLINGSHOT_IS_RESIDENCY_SCHEDULER 1
#define SLINGSHOT_IS_PINBALL_COMPRESSOR 0
#define MODEL_SIZE_NE_RESIDENT_WORKING_SET 1
#define MMAP_ONCE_PER_SHARD 1
#define TENSOR_VIEW_ZERO_COPY 1
#define LAYER_WINDOW_NOT_PER_TENSOR_MAP 1
#define EXPERT_CACHE_BOUNDED 1
#define PREFETCH_OVERLAPS_SPIN 1
#define PINBALL_THRASH_ON_CRITICAL_PATH 0
#define BENCH_COMPRESSION_RATIO_NE_DECODE_TPS 1
/*
  GGUF directory → TileAddress → mmap view → bounded residency → kernel
  TPS still = BANDWIDTH / EFFECTIVE_BYTES_PER_TOKEN
  Do not wire pinball reconstruct into generateStream.
*/
