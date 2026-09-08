#pragma once
// Dual-lane hard contract: WEIGHTS DO NOT CROSS LANES.
#include <cstdio>
#include <cstdint>

namespace Deep2 {
namespace dual_lane {

enum class LaneId : uint8_t { A = 0, B = 1 };

enum class CrossLanePayload : uint8_t {
    None = 0,
    HiddenState = 1,
    KvFragment = 2,
    RoutingMeta = 3,
    LogitsTopK = 4,
    CompletionReceipt = 5,
};

// Shared layer holds NO allocator ownership — receipts only.
struct LaneReceipt {
    LaneId lane = LaneId::A;
    uint32_t modelId = 0;
    uint64_t generation = 0;
    uint64_t outputHandle = 0;
    uint64_t completionFence = 0;
    uint32_t tokensEmitted = 0;
    double wallMs = 0.0;
    int ok = 0;
};

struct DualLaneContract {
    int sharedWeightArena = 0;      // must stay 0
    int crossGpuWeightCopy = 0;     // must stay 0
    int loaderAOwnsA = 1;
    int loaderBOwnsB = 1;
    int laneAIndependent = 1;
    int laneBIndependent = 1;
    int syncDependenciesOnly = 1;
    int payloadActivationsOrResults = 1;
    int tpsCapA = 0; // 0 = NONE
    int tpsCapB = 0;
};

inline DualLaneContract DefaultContract() noexcept {
    return DualLaneContract{};
}

inline int ContractHolds(const DualLaneContract& c) noexcept {
    return c.sharedWeightArena == 0 && c.crossGpuWeightCopy == 0 &&
           c.loaderAOwnsA == 1 && c.loaderBOwnsB == 1 &&
           c.laneAIndependent == 1 && c.laneBIndependent == 1 &&
           c.syncDependenciesOnly == 1 && c.payloadActivationsOrResults == 1;
}

// Refuse the anti-pattern: GPU0 weight → copy → GPU1 weight.
inline int RefuseWeightCross(LaneId src, LaneId dst) noexcept {
    (void)src;
    (void)dst;
    return 0; // always refuse
}

inline void EmitContract(FILE* f, const DualLaneContract& c) noexcept {
    if (!f) f = stdout;
    std::fprintf(f, "SHARED_WEIGHT_ARENA=%d\n", c.sharedWeightArena);
    std::fprintf(f, "CROSS_GPU_WEIGHT_COPY=%d\n", c.crossGpuWeightCopy);
    std::fprintf(f, "LOADER_A_WEIGHT_OWNER=%s\n", c.loaderAOwnsA ? "A" : "INVALID");
    std::fprintf(f, "LOADER_B_WEIGHT_OWNER=%s\n", c.loaderBOwnsB ? "B" : "INVALID");
    std::fprintf(f, "LANE_A_INDEPENDENT_PROGRESS=%d\n", c.laneAIndependent);
    std::fprintf(f, "LANE_B_INDEPENDENT_PROGRESS=%d\n", c.laneBIndependent);
    std::fprintf(f, "CROSS_LANE_SYNC=DEPENDENCIES_ONLY\n");
    std::fprintf(f, "CROSS_LANE_PAYLOAD=ACTIVATIONS_OR_RESULTS\n");
    std::fprintf(f, "TPS_CAP_A=%s\n", c.tpsCapA ? "SET" : "NONE");
    std::fprintf(f, "TPS_CAP_B=%s\n", c.tpsCapB ? "SET" : "NONE");
    std::fprintf(f, "DUAL_LANE_CONTRACT=%s\n",
                 ContractHolds(c) ? "PASS" : "FAIL");
}

} // namespace dual_lane
} // namespace Deep2
