#pragma once
/* ScoreboardInvariants — GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001 ≤99.
   Architecture LOCKED. LIVE remains 0 until product decode polls nextRunnable. */
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

enum : int {
    INVERSION_LOCKED = 1,
    MODEL_SIZE_NE_RESIDENCY = 1,
    LOADMODEL_DEMOTED_TO_OPEN_INDEX = 1,
    SCOREBOARD_IS_SCHEDULER_AUTHORITY = 1,
    WAIT_PER_LAYER = 0,            /* architecture target */
    WAIT_PER_LAYER_LIVE = 0,       /* joins still in ForwardMLALayers */
    SCOREBOARD_WAIT_PER_LAYER = 1, /* fail-closed until LIVE */
    SCOREBOARD_SCHEDULER_LIVE = 0,
    TPS_LIMIT_NONE = 1,
    RAW_TPS_TOKENS_OVER_WALL = 1,
    TELEMETRY_NE_SCHEDULER = 1,
    DEQUANT_AT_TILE_ONLY = 1,
    QUANTIZED_UNTIL_KERNEL = 1, /* alias: unpack only in register tiles */
    BAN_PERSISTENT_F16_F32_WEIGHT_WINDOWS = 1,
    MODEL_OPEN_ALLOC_PROPORTIONAL_TO_MODEL_BYTES = 0,
    DEVICE_ELASTICITY_LAYER_MOD_N = 0,
    MULTI_GPU_COST_SCORED = 1,
    DUALSTICK_REOPEN = 0,
    PROMOTE = 0,
    TIP_CLIMB_HOLD = 1
};

enum : uint32_t {
    kWorkingWindowsDefault = 4,
    kKvPagePoolFixed = 1,
    kStagingRingSlots = 2
};

inline constexpr const char* kTpsLimit = "NONE";

} /* namespace scoreboard */
} /* namespace Deep2 */
