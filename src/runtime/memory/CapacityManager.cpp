// ============================================================================
// CapacityManager.cpp
// ============================================================================
#include "CapacityManager.hpp"
#include <algorithm>

namespace RawrXD {
namespace Memory {

CapacityManager::CapacityManager(CapacityPolicy policy)
    : m_policy(policy) {}

void CapacityManager::registerPool(const DeviceMemoryPool& pool) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto& p        = m_pools[pool.device];
    p              = pool;
    p.highWatermark = pool.used;
    p.emergencyReserve = static_cast<uint64_t>(
        pool.capacity * m_policy.emergencyReserve);
}

void CapacityManager::registerSystemRAM(uint64_t capacityBytes) {
    DeviceMemoryPool p;
    p.device           = kSystemRAMDevice;
    p.capacity         = capacityBytes;
    p.emergencyReserve = static_cast<uint64_t>(
        capacityBytes * m_policy.emergencyReserve);
    registerPool(p);
}

void CapacityManager::setBudget(DeviceId device, const RuntimeMemoryBudget& budget) {
    std::unique_lock<std::mutex> lk(m_mtx);
    m_budgets[device] = budget;
}

uint64_t CapacityManager::effectiveCapacity(const DeviceMemoryPool& p) const noexcept {
    // Effective = capacity - emergency reserve.
    if (p.emergencyReserve >= p.capacity) return 0;
    return p.capacity - p.emergencyReserve;
}

bool CapacityManager::canFit(DeviceId device, MemoryTier /*tier*/, uint64_t bytes) const {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_pools.find(device);
    if (it == m_pools.end()) return false;
    const auto& p = it->second;
    uint64_t eff = effectiveCapacity(p);
    if (p.used + p.reserved + bytes > eff) return false;
    // Enforce prefetch ceiling.
    double projected = static_cast<double>(p.used + p.reserved + bytes) /
                       static_cast<double>(p.capacity);
    return projected <= m_policy.prefetchCeiling;
}

bool CapacityManager::reserve(DeviceId device, MemoryTier /*tier*/, uint64_t bytes) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_pools.find(device);
    if (it == m_pools.end()) return false;
    auto& p = it->second;
    uint64_t eff = effectiveCapacity(p);
    if (p.used + p.reserved + bytes > eff) return false;
    p.reserved += bytes;
    return true;
}

void CapacityManager::release(DeviceId device, MemoryTier /*tier*/, uint64_t bytes) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_pools.find(device);
    if (it == m_pools.end()) return;
    auto& p = it->second;
    if (p.reserved >= bytes)        p.reserved -= bytes;
    else { p.used = (p.used > bytes - p.reserved) ? p.used - (bytes - p.reserved) : 0; p.reserved = 0; }
    p.highWatermark = std::max(p.highWatermark, p.used + p.reserved);
}

DeviceMemoryPool CapacityManager::poolState(DeviceId device) const {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_pools.find(device);
    if (it == m_pools.end()) { DeviceMemoryPool p; p.device = device; return p; }
    return it->second;
}

std::vector<DeviceId> CapacityManager::vramDevices() const {
    std::unique_lock<std::mutex> lk(m_mtx);
    std::vector<DeviceId> out;
    for (auto& [id, _] : m_pools)
        if (id != kSystemRAMDevice) out.push_back(id);
    return out;
}

double CapacityManager::utilization(DeviceId device) const {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_pools.find(device);
    if (it == m_pools.end() || it->second.capacity == 0) return 0.0;
    return static_cast<double>(it->second.used + it->second.reserved) /
           static_cast<double>(it->second.capacity);
}

bool CapacityManager::anyPoolOverCeiling() const {
    std::unique_lock<std::mutex> lk(m_mtx);
    for (auto& [id, p] : m_pools) {
        if (p.capacity == 0) continue;
        double u = static_cast<double>(p.used + p.reserved) /
                   static_cast<double>(p.capacity);
        if (u > m_policy.prefetchCeiling) return true;
    }
    return false;
}

void CapacityManager::setPolicy(const CapacityPolicy& policy) {
    std::unique_lock<std::mutex> lk(m_mtx);
    m_policy = policy;
}

CapacityPolicy CapacityManager::policy() const {
    std::unique_lock<std::mutex> lk(m_mtx);
    return m_policy;
}

} // namespace Memory
} // namespace RawrXD
