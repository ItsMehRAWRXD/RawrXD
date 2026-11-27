// ReapAdmission.hpp — RAWRXD S03.8 (hardware-aware allocation admission)
// Consumes the C03 planner + S03.7 retirement ledger to decide admission.
// Enforces separate RAM/VRAM, accounts pending-retirement bytes, rejects
// infeasible plans explicitly (no silent fallback). Storage-independent; no RNG.
#pragma once
#include "reap/ReapPlanner.hpp"
#include <cstdint>

namespace RawrXD::Reap {

struct Admission {
    bool admit = false;
    Plan plan;
    uint64_t pendingRetirement = 0;
    std::string reason;
};

// Decide admission for a transformation under capacity + geometry + pending retirement.
inline Admission Admit(const Capacity& cap, const ModelGeom& g, uint64_t targetBytes,
                       uint32_t mode, uint64_t pendingRetirementBytes) {
    Admission a;
    a.pendingRetirement = pendingRetirementBytes;
    // Pending-retirement memory is not yet reclaimable: add to required base.
    ModelGeom g2 = g;
    if (pendingRetirementBytes > (uint64_t)-1 - g2.scratchBytes) { a.reason = "retirement overflow"; return a; }
    g2.scratchBytes += pendingRetirementBytes;
    a.plan = PlanReap(cap, g2, targetBytes, mode);
    if (!a.plan.feasible) { a.reason = a.plan.reason.empty() ? "infeasible" : a.plan.reason; return a; }
    a.admit = true; a.reason = "admitted";
    return a;
}

} // namespace RawrXD::Reap