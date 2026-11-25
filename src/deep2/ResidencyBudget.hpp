// ============================================================================
// ResidencyBudget.hpp — DEEP2_ADMISSION_BUDGET_001
//
// Admission arithmetic for device-local VRAM.  The defect this closes:
// physical VRAM capacity was treated as currently-allocatable capacity, so a
// shared GPU with 7.5 GiB free but 32 GiB total admitted a 17 GiB model and
// then spilled.  These helpers compute *usable* capacity from a live budget
// (VK_EXT_memory_budget / DXGI QueryVideoMemoryInfo) with saturating
// subtraction, and admit a model only when weights + KV + scratch + staging
// all fit the usable capacity.
//
// Header-only, no dependencies.  Pure arithmetic; the caller supplies the
// measured ResidencyBudget and the reservations.  This does not itself query
// the driver — see Deep2DeviceManager (DXGI) and vulkan_compute
// (VK_EXT_memory_budget) for the measurements that populate it.
// ============================================================================
#ifndef RAWRXD_DEEP2_RESIDENCY_BUDGET_HPP
#define RAWRXD_DEEP2_RESIDENCY_BUDGET_HPP

#include <cstdint>
#include <algorithm>

namespace Deep2 {

// Saturating subtraction: a - b, clamped at 0 (never wraps).
constexpr uint64_t satSub(uint64_t a, uint64_t b) noexcept {
    return a > b ? a - b : 0;
}

// A device's live residency budget.  All fields are MEASURED by the caller:
//   physical : total device-local VRAM (DXGI DedicatedVideoMemory)
//   budget   : VK_EXT_memory_budget heap budget (0 if unsupported)
//   usage    : VK_EXT_memory_budget heap usage  (0 if unsupported)
//   pending  : bytes reserved by other in-flight admissions not yet reflected
//              in `usage` (0 if none)
//   margin   : safety headroom the policy keeps free (driver + arenas)
struct ResidencyBudget {
    uint64_t physical = 0;
    uint64_t budget = 0;
    uint64_t usage = 0;
    uint64_t pending = 0;
    uint64_t margin = 0;
};

// Usable device-local bytes = min(physical, budget) - usage - pending - margin,
// every subtraction saturating.  When the budget is unknown (budget == 0) the
// physical capacity is used, preserving the pre-existing behaviour for drivers
// without VK_EXT_memory_budget.
inline uint64_t usableVRAM(const ResidencyBudget& b) noexcept {
    const uint64_t cap = b.budget ? std::min(b.physical, b.budget) : b.physical;
    return satSub(satSub(satSub(cap, b.usage), b.pending), b.margin);
}

// True iff weights + kv + scratch + staging all fit the usable capacity.
// Each requirement is checked and subtracted in turn so a single oversized
// class is rejected without underflow.
inline bool admitModel(const ResidencyBudget& b,
                       uint64_t weights,
                       uint64_t kv,
                       uint64_t scratch,
                       uint64_t staging) noexcept {
    uint64_t remaining = usableVRAM(b);
    const uint64_t requirements[] = { weights, kv, scratch, staging };
    for (uint64_t bytes : requirements) {
        if (bytes > remaining) return false;
        remaining -= bytes;
    }
    return true;
}

} // namespace Deep2

#endif // RAWRXD_DEEP2_RESIDENCY_BUDGET_HPP