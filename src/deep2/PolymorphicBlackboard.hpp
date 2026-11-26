// PolymorphicBlackboard.hpp — RAWRXD_POLYMORPHIC_INTEGRATION_004
//
// RNG-free production blackboard: integrates PolymorphicEngine with the
// ExecutorFn real-inference seam. No random_device, distributions, randomized
// acceptance or predetermined temperature. Candidate generation is
// observation-driven (predErr/stagnation), NOT step%5. The configurable neutral
// ratio (default 50 50) is enforced by allocation accounting. Deterministic
// LMS prediction correction; measured-vs-measured acceptance; repeated
// validation before promotion; bounded volatile memory. No fabricated results.
#pragma once
#include "PolymorphicEngine.hpp"
#include <vector>
#include <cmath>
#include <algorithm>

namespace rawrxd {
namespace polybb {

struct Measured { double prefillTps = 0, decodeTps = 0; int tokens = 0; bool consistent = false, valid = false; };
using ExecutorFn = bool (*)(const poly::Cand&, Measured&);

struct Blackboard {
    poly::Ratio ratio;                 // 50 50 default, runtime-configurable
    poly::State st;
    std::vector<poly::Cand> obs;       // bounded
    poly::Cand current, best;
    double bestDecode = 0; int bestRepeats = 0; bool haveBest = false;
    poly::Cand pending; double pendingDecode = 0; int pendingRepeats = 0; bool havePending = false;
    uint64_t alloc0 = 0, alloc1 = 0, iters = 0, accepts = 0, rejects = 0, failures = 0;
    uint64_t successes = 0;          // monotonic successful-execution counter (bounded-safe)
    double a = 0, b = 0, c = 0, residVar = 1.0;  // deterministic LMS
    size_t cap = 256;
};

static inline double Predict(const Blackboard& bb, const poly::Cand& c) {
    return bb.a + bb.b * (c.batch / 512.0) + bb.c * (c.threads / 32.0);
}
static inline void Correct(Blackboard& bb, const poly::Cand& c, double actual) {
    const double nb = c.batch / 512.0, nt = c.threads / 32.0;
    const double err = actual - (bb.a + bb.b * nb + bb.c * nt);
    const double lr = 0.01;
    bb.a += lr * err; bb.b += lr * err * nb; bb.c += lr * err * nt;
    bb.residVar = 0.98 * bb.residVar + 0.02 * err * err;
}

// Ratio allocation accounting: the ratio is the PRIMARY deterministic allocator
// (family behind its target share is chosen). Observed state then drives the
// candidate WITHIN the family (NextObs) — ratio allocates, observations behave.
static inline int AllocSelect(const Blackboard& bb) {
    const uint64_t tot = bb.alloc0 + bb.alloc1 + 1;
    const double share0 = static_cast<double>(bb.alloc0) / static_cast<double>(tot);
    const double target0 = static_cast<double>(bb.ratio.a) / 100.0;
    return (share0 < target0) ? 0 : 1;
}

// Observation-driven candidate (predErr/stagnation), not step%5.
static inline poly::Cand NextObs(const Blackboard& bb) {
    const int fam = AllocSelect(bb);
    const int off = (int)(bb.st.predErr) % 7 - 3;   // from prediction error
    poly::Cand c;
    if (fam == 0) { c.batch = std::max(1, bb.st.bestBatch + off * 32); c.threads = std::max(1, bb.st.bestThreads + off); }
    else { const int k = bb.st.stagnation % 8; c.batch = 16 + k * 64; c.threads = 1 + k * 4; }
    c.batch = std::min(4096, c.batch);
    return c;
}

// Authoritative execution receipt: the ACTUAL candidate run and its result.
struct StepResult { poly::Cand cand; Measured m; bool success = false; };

// One deterministic cycle: predict -> execute -> correct -> accept -> validate.
// Returns an authoritative receipt (single candidate selection; no double-pick).
static inline StepResult Step(Blackboard& bb, ExecutorFn exec) {
    StepResult R;
    ++bb.iters;
    const int fam = AllocSelect(bb);
    R.cand = (bb.havePending && bb.pendingRepeats == 1) ? bb.pending : NextObs(bb);
    if (fam == 0) ++bb.alloc0; else ++bb.alloc1;     // ratio allocation accounting
    Measured m;
    if (!exec(R.cand, m) || !m.valid || m.decodeTps <= 0) {
        ++bb.failures; ++bb.rejects; R.success = false; return R;
    }
    R.success = true; R.m = m; ++bb.successes;        // monotonic (bounded-safe)
    const poly::Cand& cand = R.cand;
    const double pred = Predict(bb, cand);
    Correct(bb, cand, m.decodeTps);
    if (bb.obs.size() >= bb.cap) bb.obs.erase(bb.obs.begin());
    bb.obs.push_back(cand);

    if (m.decodeTps >= bb.st.curDecode) { bb.current = cand; bb.st.curDecode = m.decodeTps; ++bb.accepts; }
    else ++bb.rejects;

    if (m.consistent) {                               // repeated validation
        if (bb.havePending && bb.pending.batch == cand.batch && bb.pending.threads == cand.threads) ++bb.pendingRepeats;
        else { bb.pending = cand; bb.pendingDecode = m.decodeTps; bb.pendingRepeats = 1; bb.havePending = true; }
        if (bb.pendingRepeats >= 2 && (!bb.haveBest || bb.pendingDecode > bb.bestDecode)) {
            bb.best = bb.pending; bb.bestDecode = bb.pendingDecode;
            bb.bestRepeats = bb.pendingRepeats; bb.haveBest = true;
        }
    }
    bb.st.step++;
    bb.st.predErr = std::fabs(pred - m.decodeTps);
    if (m.decodeTps > bb.st.bestDecode) bb.st.stagnation = 0; else ++bb.st.stagnation;
    bb.st.bestDecode = bb.bestDecode;
    return R;
}

} // namespace polybb
} // namespace rawrxd