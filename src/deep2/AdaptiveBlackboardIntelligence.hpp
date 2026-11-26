// AdaptiveBlackboardIntelligence.hpp — RAWRXD_ADAPTIVE_BLACKBOARD_INTELLIGENCE_001
//
// Small native adaptive intelligence. The RULES are fixed; the next DECISION is
// not. A lightweight evolutionary search explores candidate execution configs,
// keeps the best MODELED candidate, and occasionally accepts weaker ones
// (probabilistic, temperature-adaptive) to escape local optima. State is a
// volatile in-memory blackboard: no persistent logging, no external deps, and
// NO fabricated benchmark results — every score is the bandwidth model applied
// to the candidate, and the actual hardware must confirm it separately.
#pragma once
#include "AdaptiveThroughputLock.hpp"
#include <vector>
#include <cmath>
#include <cstdint>

namespace rawrxd {
namespace blackboard {

struct Candidate {
    double batch        = 32.0;
    double utilization  = 0.80;
    double overlap      = 1.0;
    double residency    = 0.95;
    double storageGbps  = 14.0;
    double spec         = 1.0;
    double overheadMs   = 0.0;
    double modeledTps   = 0.0;
};

struct Blackboard {
    Candidate  current;
    Candidate  best;
    double     temperature = 1.0;
    uint64_t   iterations  = 0;
    uint64_t   accepts     = 0;
    uint64_t   rejects     = 0;
    uint64_t   rngState    = 0x9E3779B97F4A7C15ull; // deterministic seed
};

static inline uint64_t NextRand(Blackboard& b) {
    b.rngState ^= b.rngState << 13;
    b.rngState ^= b.rngState >> 7;
    b.rngState ^= b.rngState << 17;
    return b.rngState;
}
static inline double RandUnit(Blackboard& b) {
    return static_cast<double>(NextRand(b) >> 11) * (1.0 / 9007199254740992.0);
}

// Score a candidate with the bandwidth model (modeled, not measured).
static inline double ScoreCandidate(const Candidate& c,
                                    const std::vector<adaptive::GpuBw>& gpus) {
    const double V = adaptive::EffectiveAggregateGbps(gpus, c.utilization, c.overlap) * 1e9;
    const double W = 18.96e9; // active weight bytes (model input)
    return adaptive::ModeledTps(W, V, c.batch, c.residency,
                                c.storageGbps * 1e9, c.spec, c.overheadMs);
}

static inline void InitBlackboard(Blackboard& b,
                                  const std::vector<adaptive::GpuBw>& gpus) {
    b.current.modeledTps = ScoreCandidate(b.current, gpus);
    b.best = b.current;
    b.temperature = 1.0;
    b.iterations = b.accepts = b.rejects = 0;
}

// One exploration cycle: generate a candidate, score it, accept if stronger or
// probabilistically weaker, update best, adapt temperature.
static inline void ExploreCycle(Blackboard& b,
                                const std::vector<adaptive::GpuBw>& gpus) {
    Candidate cand = b.current;
    cand.batch       = 16.0 + RandUnit(b) * 240.0;  // 16..256
    cand.utilization = 0.50 + RandUnit(b) * 0.50;   // 0.50..1.0
    cand.residency   = 0.80 + RandUnit(b) * 0.20;   // 0.80..1.0
    cand.spec        = 1.0  + RandUnit(b) * 3.0;    // 1..4
    cand.modeledTps  = ScoreCandidate(cand, gpus);

    const double cur = b.current.modeledTps;
    bool accept = cand.modeledTps >= cur;
    if (!accept && b.temperature > 0.0) {
        const double scale = (cur > 0.0 ? cur : 1.0);
        const double p = std::exp((cand.modeledTps - cur) / (b.temperature * scale));
        accept = RandUnit(b) < p;                    // probabilistic weaker accept
    }
    if (accept) { b.current = cand; ++b.accepts; } else { ++b.rejects; }
    if (cand.modeledTps > b.best.modeledTps) b.best = cand;

    // Adapt temperature: cool as iterations accumulate (anneal), floor 0.05.
    b.temperature = 0.05 + 0.95 * std::exp(-0.01 * static_cast<double>(b.iterations % 500));
    ++b.iterations;
}

} // namespace blackboard
} // namespace rawrxd