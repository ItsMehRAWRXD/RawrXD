#pragma once
/* MultiGpuScoreboardCost — ChooseGpu by predicted micros. BAN layer%2.
   GATE=G3_DEEP2_SCOREBOARD_SCHEDULER_LAW_001 LIVE=0. ≤99. */
#include "ScoreboardInvariants.hpp"
#include "ScoreboardTypes.hpp"
#include <cstdint>
#include <limits>

namespace Deep2 {
namespace scoreboard {

struct GpuCostState {
    DeviceId device = -1;
    int available = 0;
    int tensorLocal = 0;
    int tensorPeer = 0;
    uint64_t tensorBytes = 0;
    uint64_t activationBytes = 0;
    double computeTflops = 0.0;
    double memoryGBs = 0.0;
    double peerGBs = 0.0;
    double hostGBs = 0.0;
    double queueMicros = 0.0;
    double launchMicros = 0.0;
};

struct GpuCostWeights {
    double compute = 1.0;
    double memory = 1.0;
    double transfer = 1.0;
    double queue = 1.0;
};

inline double BytesToMicros(uint64_t bytes, double gbPerSec) noexcept {
    if (gbPerSec <= 0.0)
        return std::numeric_limits<double>::infinity();
    return (static_cast<double>(bytes) / (gbPerSec * 1.0e9)) * 1.0e6;
}

inline double ComputeMicros(double workTflop, double deviceTflops) noexcept {
    if (deviceTflops <= 0.0)
        return std::numeric_limits<double>::infinity();
    return (workTflop / deviceTflops) * 1.0e6;
}

inline double ScoreGpu(const GpuCostState& g, double workTflop,
                       const GpuCostWeights& w = {}) noexcept {
    if (!g.available)
        return std::numeric_limits<double>::infinity();
    const double compute = ComputeMicros(workTflop, g.computeTflops);
    const double memory = BytesToMicros(g.tensorBytes, g.memoryGBs);
    double transfer = 0.0;
    if (!g.tensorLocal) {
        transfer = g.tensorPeer ? BytesToMicros(g.tensorBytes, g.peerGBs)
                                : BytesToMicros(g.tensorBytes, g.hostGBs);
    }
    transfer += BytesToMicros(g.activationBytes,
                              g.tensorPeer ? g.peerGBs : g.hostGBs);
    return g.launchMicros + w.compute * compute + w.memory * memory +
           w.transfer * transfer + w.queue * g.queueMicros;
}

/* Fail-down: unavailable device → inf → never chosen. No layer%N. */
inline DeviceId ChooseGpu(const GpuCostState* gpu, uint32_t count,
                          double workTflop,
                          const GpuCostWeights& weights = {}) noexcept {
    DeviceId best = -1;
    double bestCost = std::numeric_limits<double>::infinity();
    if (!gpu || !count || !MULTI_GPU_COST_SCORED || DEVICE_ELASTICITY_LAYER_MOD_N)
        return best;
    for (uint32_t i = 0; i < count; ++i) {
        const double cost = ScoreGpu(gpu[i], workTflop, weights);
        if (cost < bestCost) {
            bestCost = cost;
            best = gpu[i].device;
        }
    }
    return best;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
