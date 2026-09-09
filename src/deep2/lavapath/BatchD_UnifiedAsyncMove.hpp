#pragma once
/* BATCH_D — unified async movement (not three queue hops).
 *
 *   Router prediction → Expert IDs → Residency priority
 *        → UnifiedAsyncMove (one scheduler job)
 *        → GPU cache
 *
 * Governing question (B011): not "can I fit the model?"
 *   → "how often do I pay to fetch something that isn't resident?"
 *
 * Certified B011 residency (unlock-1B-Q4_K_M, B011/performance/b011_vs_b010.json):
 *   hit_rate_pct      ~79.96%
 *   bytes_reduction   ~77.6%–78.6% I/O
 *   maps_reduction    ~99.7%
 *
 * MoE is ideal: router announces the next working set before compute.
 * A small Hot GPU cache services a gigantic model when the active
 * expert set is stable enough that fetch cost is rare.
 *
 * FreeToken micro-zones: fixed overwrite addresses (never realloc).
 * Dual GPU = two sticks rubbed — zone%2 → stick. Active window = 1.
 *
 * Future-consumer space grows with model (20→671B); physical page pool does not.
 * PAST_OWNER → FUTURE_OWNER; FREE_REQUIRED=0; REUSE_REQUIRED=1.
 *
 * Ownership transfer (CopyArenaHiddenTo) waits on readiness only.
 * VRAM budget is not a placement gate (DEEP2_COST_VRAM_GATE=0).
 */
#define BATCH_D_UNIFIED_ASYNC_MOVE 1
#define BATCH_D_OWNERSHIP_READY_GATE 1
#define BATCH_D_VRAM_NOT_PLACEMENT_GATE 1
#define BATCH_D_B011_FETCH_COST_FRAME 1
#define BATCH_D_FREETOKEN_MICROZONE 1
#define BATCH_D_FUTURE_CONSUMER_SPACE 1
#define BATCH_D_HIERARCHY_VRAM_RAM_NVME 1
#define BATCH_D_B011_HIT_RATE_REF_PCT 79.96
#define BATCH_D_B011_IO_REDUCTION_REF_PCT 77.6
#define BATCH_D_B011_MAP_REDUCTION_REF_PCT 99.7
/*
 * Hierarchy (not "48 GB VRAM only"):
 *   VRAM 48 GB (R9700+7800XT) FAST → System RAM MEDIUM → NVMe TBs SLOW/LARGE
 * Runtime places working set; UnifiedAsyncMove is one Cold→Hot job.
 */
