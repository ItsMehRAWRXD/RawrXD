// AdaptiveBlackboardIntelligenceV3.hpp — RAWRXD_ADAPTIVE_BLACKBOARD_INTELLIGENCE_V3
//
// Evolves the V1 blackboard: adaptive mutation from prior outcomes (not pure
// random), a Pareto frontier of (prefill, decode) tradeoffs, a volatile
// observation matrix, dynamic temperature (heat on stagnation, cool on
// improvement), and best-validated retention. No hardcoded "optimal" config —
// the next move is always discovered. Zero persistent logging; all state is RAM.
// Scores are the bandwidth MODEL (modeled), never measured hardware results.
#pragma once
#include "AdaptiveThroughputLock.hpp"
#include <vector>
#include <cmath>
#include <cstdint>
#include <algorithm>

namespace rawrxd {
namespace blackboard_v3 {

struct Obs {
    double batch = 32.0, util = 0.80, residency = 0.95, spec = 1.0;
    double prefillTps = 0.0, decodeTps = 0.0;
};

struct V3Blackboard {
    std::vector<Obs> obs;     // volatile observation matrix
    std::vector<Obs> pareto;  // non-dominated (prefill, decode) frontier
    Obs   current;
    Obs   best;               // best validated (by decode)
    double temperature = 1.0;
    uint64_t iterations = 0, accepts = 0, rejects = 0;
    uint64_t rngState = 0x9E3779B97F4A7C15ull;
};

static inline uint64_t NextRand(V3Blackboard& b) {
    b.rngState ^= b.rngState << 13; b.rngState ^= b.rngState >> 7; b.rngState ^= b.rngState << 17;
    return b.rngState;
}
static inline double RandUnit(V3Blackboard& b) {
    return static_cast<double>(NextRand(b) >> 11) * (1.0 / 9007199254740992.0);
}
static inline double Gauss(V3Blackboard& b) { // Box-Muller
    const double u = (RandUnit(b) > 1e-12) ? RandUnit(b) : 1e-12;
    const double v = RandUnit(b);
    return std::sqrt(-2.0 * std::log(u)) * std::cos(6.283185307179586 * v);
}
static inline double Clamp(double x, double lo, double hi) {
    return x < lo ? lo : (x > hi ? hi : x);
}

// Score a config into (prefill, decode) modeled TPS. Prefill scales with batch;
// decode is single-stream (batch=1).
static inline void Score(Obs& o, const std::vector<adaptive::GpuBw>& gpus) {
    const double V = adaptive::EffectiveAggregateGbps(gpus, o.util, 1.0) * 1e9;
    const double W = 18.96e9;
    o.prefillTps = adaptive::ModeledTps(W, V, o.batch, o.residency, 0.0, o.spec, 0.0);
    o.decodeTps  = adaptive::ModeledTps(W, V, 1.0,   o.residency, 0.0, o.spec, 0.0);
}

static inline bool Dominates(const Obs& a, const Obs& b) {
    return a.prefillTps >= b.prefillTps && a.decodeTps >= b.decodeTps &&
           (a.prefillTps > b.prefillTps || a.decodeTps > b.decodeTps);
}
static inline void ParetoInsert(std::vector<Obs>& front, const Obs& c) {
    for (const auto& e : front) if (Dominates(e, c)) return; // c dominated
    front.erase(std::remove_if(front.begin(), front.end(),
        [&](const Obs& e){ return Dominates(c, e); }), front.end());
    front.push_back(c);
}

static inline void InitV3(V3Blackboard& b, const std::vector<adaptive::GpuBw>& gpus) {
    b.obs.clear(); b.pareto.clear();
    Score(b.current, gpus);
    b.best = b.current;
    b.temperature = 1.0; b.iterations = b.accepts = b.rejects = 0;
    ParetoInsert(b.pareto, b.current);
}

static inline void ExploreCycleV3(V3Blackboard& b,
                                  const std::vector<adaptive::GpuBw>& gpus) {
    Obs cand;
    if (RandUnit(b) < 0.70) {                 // adaptive mutation of current
        cand = b.current;
        cand.batch     = Clamp(b.current.batch * std::exp(Gauss(b) * 0.30), 16.0, 512.0);
        cand.util      = Clamp(b.current.util + Gauss(b) * 0.05, 0.50, 1.0);
        cand.residency = Clamp(b.current.residency + Gauss(b) * 0.02, 0.80, 1.0);
        cand.spec      = Clamp(b.current.spec + Gauss(b) * 0.30, 1.0, 4.0);
    } else {                                  // pure random exploration
        cand.batch     = 16.0 + RandUnit(b) * 496.0;
        cand.util      = 0.50 + RandUnit(b) * 0.50;
        cand.residency = 0.80 + RandUnit(b) * 0.20;
        cand.spec      = 1.0  + RandUnit(b) * 3.0;
    }
    Score(cand, gpus);

    const double prevBest = b.best.decodeTps;
    bool accept = cand.decodeTps >= b.current.decodeTps;
    if (!accept && b.temperature > 0.0) {
        const double scale = (b.current.decodeTps > 0 ? b.current.decodeTps : 1.0);
        accept = RandUnit(b) < std::exp((cand.decodeTps - b.current.decodeTps) /
                                        (b.temperature * scale));
    }
    if (accept) { b.current = cand; ++b.accepts; } else ++b.rejects;
    if (cand.decodeTps > b.best.decodeTps) b.best = cand;   // best validated
    ParetoInsert(b.pareto, cand);                            // Pareto frontier
    b.obs.push_back(cand);                                   // observation matrix

    // Dynamic temperature: cool on improvement, heat on stagnation.
    if (b.best.decodeTps > prevBest) b.temperature = std::max(0.05, b.temperature * 0.95);
    else                             b.temperature = std::min(1.0,  b.temperature * 1.05 + 0.01);
    ++b.iterations;
}

} // namespace blackboard_v3
} // namespace rawrxd