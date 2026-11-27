// ReapPlanner.hpp — RAWRXD C03 (hardware-aware transformation planner)
// Determines a feasible REAP execution configuration from actual capacity +
// model geometry + mode. Overflow-safe; rejects infeasible plans explicitly
// (never silently exceeds budget). Storage-independent; no RNG.
#pragma once
#include <cstdint>
#include <string>
#include <limits>

namespace RawrXD::Reap {

struct Capacity {
    uint64_t hostRamBytes = 0;
    uint64_t dedicatedVramBytes = 0;
    uint64_t sharedVramBytes = 0;
    uint32_t devices = 1;
};
struct ModelGeom {
    uint64_t nonexpertBytes = 0;    // non-expert tensor storage
    uint64_t expertBytesTotal = 0;  // all experts
    uint64_t kvBytes = 0;           // KV cache
    uint64_t scratchBytes = 0;      // scratch/staging/descriptors/overhead
    uint32_t expertCount = 0;
};
struct Plan {
    bool feasible = false;
    std::string reason;
    uint64_t availableBytes = 0;
    uint64_t peakBytes = 0;
    uint64_t workingSetBytes = 0;
    uint32_t retainedExperts = 0;
};

static inline bool AddOverflow(uint64_t a, uint64_t b, uint64_t& out) {
    if (a > std::numeric_limits<uint64_t>::max() - b) return false;
    out = a + b; return true;
}

// C03: plan retained-expert count / working set for a mode (0=Physical,1=Virtual,2=Streaming).
inline Plan PlanReap(const Capacity& cap, const ModelGeom& g, uint64_t targetBytes, uint32_t mode) {
    Plan p;
    uint64_t avail = cap.hostRamBytes;
    if (mode != 0 && cap.dedicatedVramBytes > 0) {
        const uint64_t vram = cap.dedicatedVramBytes + cap.sharedVramBytes;
        if (vram < avail) avail = vram;   // GPU modes constrained by VRAM
    }
    p.availableBytes = avail;
    uint64_t base = 0;
    if (!AddOverflow(g.nonexpertBytes, g.kvBytes, base) || !AddOverflow(base, g.scratchBytes, base)) {
        p.reason = "size overflow"; return p;
    }
    if (base > avail) { p.reason = "base (nonexpert+kv+scratch) exceeds capacity"; return p; }
    // Retain as many experts as fit under the target and capacity.
    const uint64_t budget = (targetBytes > 0 && targetBytes < avail) ? targetBytes : avail;
    uint64_t expertBudget = (budget > base) ? (budget - base) : 0;
    uint32_t retain = 0;
    if (g.expertCount > 0 && g.expertBytesTotal > 0) {
        const uint64_t perExpert = g.expertBytesTotal / g.expertCount;
        retain = (uint32_t)(expertBudget / (perExpert ? perExpert : 1));
        if (retain > g.expertCount) retain = g.expertCount;
    }
    uint64_t expertUsed = (uint64_t)retain * (g.expertBytesTotal / (g.expertCount ? g.expertCount : 1));
    uint64_t peak = 0;
    if (!AddOverflow(base, expertUsed, peak)) { p.reason = "peak overflow"; return p; }
    p.peakBytes = peak; p.workingSetBytes = expertUsed; p.retainedExperts = retain;
    if (peak > avail) { p.reason = "peak exceeds capacity"; return p; }
    p.feasible = true; p.reason = "ok"; return p;
}

} // namespace RawrXD::Reap