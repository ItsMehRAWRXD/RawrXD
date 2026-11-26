// PolymorphicEngine.hpp — RAWRXD_BLACKBOARD_FINAL_IMPLEMENTATION (Package 2)
//
// Deterministic, RNG-free strategy engine for the adaptive blackboard.
//   * Configurable, semantically NEUTRAL ratio (default 50 50; any complementary
//     pair e.g. 20 80 / 30 70). The ratio only allocates between two strategy
//     families — it carries no cognitive meaning.
//   * Strategy selection is a deterministic function of OBSERVED STATE
//     (prediction error, stagnation, best-vs-current), never random numbers,
//     artificial entropy or a predetermined temperature schedule.
//   * Candidate parameters are derived deterministically from state (no RNG, no
//     fixed alternating sequence). Same observations -> same decisions
//     (deterministic replay); different observations -> different behavior.
#pragma once
#include <cstdint>
#include <cmath>
#include <algorithm>

namespace rawrxd {
namespace poly {

// Semantically neutral, runtime-configurable allocation ratio (sums to 100).
struct Ratio {
    int a = 50, b = 50;
    void set(int x, int y) { a = x; b = y; }      // runtime modification
    bool valid() const { return a >= 0 && b >= 0 && (a + b) == 100; }
};

// Observed internal state (all derived from real measurements / predictions).
struct State {
    double   predErr = 0.0;    // recent prediction error magnitude
    double   bestDecode = 0.0; // best measured decode so far
    double   curDecode = 0.0;  // current measured decode
    int      stagnation = 0;   // steps since best improved
    uint64_t step = 0;         // deterministic step counter
    int      bestBatch = 32, bestThreads = 8;
};

// Deterministic strategy: 0 = intensify (mutate around best), 1 = diversify.
inline int SelectStrategy(const Ratio& r, const State& s) {
    double sa = (s.predErr > 1.0 ? 1.0 : 0.0) + (s.stagnation > 5 ? 1.0 : 0.0);
    double sb = (s.bestDecode > s.curDecode ? 1.0 : 0.0) + (s.stagnation <= 5 ? 1.0 : 0.0);
    sa *= static_cast<double>(r.a) / 50.0;        // ratio allocation bias (neutral at 50/50)
    sb *= static_cast<double>(r.b) / 50.0;
    return (sa >= sb) ? 0 : 1;                    // deterministic (no RNG)
}

struct Cand { int batch; int threads;
    bool operator==(const Cand& o) const { return batch == o.batch && threads == o.threads; } };

// Deterministic candidate from state (no RNG, no fixed alternation).
inline Cand NextCandidate(const Ratio& r, const State& s) {
    const int strat = SelectStrategy(r, s);
    const int n = static_cast<int>(s.step % 5);   // deterministic 0..4
    Cand c;
    if (strat == 0) {                             // intensify around best
        c.batch   = std::max(1, s.bestBatch + (n - 2) * 32);
        c.threads = std::max(1, s.bestThreads + (n - 2));
    } else {                                      // diversify
        c.batch   = 16 + n * 96;
        c.threads = 1 + n * 6;
    }
    c.batch = std::min(4096, c.batch);
    return c;
}

} // namespace poly
} // namespace rawrxd