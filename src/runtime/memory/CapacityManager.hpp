// ============================================================================
// CapacityManager.hpp
// Per-device pool accounting and budget enforcement.
// ============================================================================
#pragma once

#include "PlacementPolicy.hpp"
#include <unordered_map>
#include <mutex>
#include <vector>

namespace RawrXD {
namespace Memory {

class CapacityManager {
public:
    explicit CapacityManager(CapacityPolicy policy = {});
    ~CapacityManager() = default;

    // Register a device pool.  Replaces any prior registration for that device.
    void registerPool(const DeviceMemoryPool& pool);

    // Register a system-RAM pool (DeviceId = UINT32_MAX by convention).
    void registerSystemRAM(uint64_t capacityBytes);

    // Set per-device runtime budget (weights, kv, staging, etc.).
    void setBudget(DeviceId device, const RuntimeMemoryBudget& budget);

    // Query: can 'bytes' fit on 'device' in 'tier' without breaching the
    // prefetch ceiling?  Does NOT commit any reservation.
    bool canFit(DeviceId device, MemoryTier tier, uint64_t bytes) const;

    // Reserve 'bytes' on the given device/tier.
    // Returns false if the allocation would breach the emergency reserve.
    bool reserve(DeviceId device, MemoryTier tier, uint64_t bytes);

    // Release a previously reserved block.
    void release(DeviceId device, MemoryTier tier, uint64_t bytes);

    // Snapshot of a pool's current state.
    DeviceMemoryPool poolState(DeviceId device) const;

    // All registered device IDs (excludes system RAM device).
    std::vector<DeviceId> vramDevices() const;

    // Utilization ratio (0..1) for a device.
    double utilization(DeviceId device) const;

    // True if any pool has exceeded its prefetch ceiling.
    bool anyPoolOverCeiling() const;

    // Update policy knobs at runtime.
    void setPolicy(const CapacityPolicy& policy);
    CapacityPolicy policy() const;

private:
    static constexpr DeviceId kSystemRAMDevice = UINT32_MAX;

    uint64_t effectiveCapacity(const DeviceMemoryPool& p) const noexcept;

    mutable std::mutex                           m_mtx;
    std::unordered_map<DeviceId, DeviceMemoryPool> m_pools;
    std::unordered_map<DeviceId, RuntimeMemoryBudget> m_budgets;
    CapacityPolicy                               m_policy;
};

} // namespace Memory
} // namespace RawrXD
