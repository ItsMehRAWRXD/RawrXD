// ============================================================================
// ResidencyTracker.cpp
// ============================================================================
#include "ResidencyTracker.hpp"
#include <chrono>

namespace RawrXD {
namespace Memory {

static uint64_t nowNs() noexcept {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}

void ResidencyTracker::track(TensorId id, uint64_t bytes) {
    std::unique_lock<std::mutex> lk(m_mtx);
    if (m_map.count(id)) return;
    TensorResidency r;
    r.id    = id;
    r.bytes = bytes;
    m_map[id] = r;
}

void ResidencyTracker::update(const TensorResidency& r) {
    std::unique_lock<std::mutex> lk(m_mtx);
    m_map[r.id] = r;
}

void ResidencyTracker::markPrefetching(TensorId id, MemoryTier dest) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_map.find(id);
    if (it == m_map.end()) return;
    it->second.state = ResidencyState::Prefetching;
    it->second.tier  = dest;
}

void ResidencyTracker::markResident(TensorId id, MemoryTier tier, uint64_t address) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_map.find(id);
    if (it == m_map.end()) return;
    it->second.tier    = tier;
    it->second.state   = ResidencyState::Resident;
    it->second.address = address;
}

void ResidencyTracker::markEvicting(TensorId id) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_map.find(id);
    if (it == m_map.end()) return;
    it->second.state = ResidencyState::Evicting;
}

void ResidencyTracker::markCold(TensorId id) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_map.find(id);
    if (it == m_map.end()) return;
    it->second.state   = ResidencyState::Cold;
    it->second.tier    = MemoryTier::UNRESIDENT;
    it->second.address = 0;
}

void ResidencyTracker::markFailed(TensorId id) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_map.find(id);
    if (it == m_map.end()) return;
    it->second.state = ResidencyState::Failed;
}

void ResidencyTracker::markPinned(TensorId id, bool pin) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_map.find(id);
    if (it == m_map.end()) return;
    it->second.pinned = pin;
    if (pin) it->second.state = ResidencyState::Pinned;
}

void ResidencyTracker::recordUse(TensorId id, uint64_t timestampNs) {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_map.find(id);
    if (it == m_map.end()) return;
    it->second.lastUse  = timestampNs ? timestampNs : nowNs();
    it->second.useCount += 1;
}

bool ResidencyTracker::known(TensorId id) const {
    std::unique_lock<std::mutex> lk(m_mtx);
    return m_map.count(id) != 0;
}

TensorResidency ResidencyTracker::get(TensorId id) const {
    std::unique_lock<std::mutex> lk(m_mtx);
    auto it = m_map.find(id);
    if (it == m_map.end()) {
        TensorResidency r; r.id = id; return r;
    }
    return it->second;
}

MemoryTier ResidencyTracker::tierOf(TensorId id) const {
    return get(id).tier;
}

ResidencyState ResidencyTracker::stateOf(TensorId id) const {
    return get(id).state;
}

bool ResidencyTracker::isResident(TensorId id) const {
    auto s = stateOf(id);
    return s == ResidencyState::Resident || s == ResidencyState::Pinned;
}

bool ResidencyTracker::isPinned(TensorId id) const {
    return get(id).pinned;
}

std::vector<TensorResidency> ResidencyTracker::byTier(MemoryTier tier) const {
    std::unique_lock<std::mutex> lk(m_mtx);
    std::vector<TensorResidency> out;
    for (auto& [id, r] : m_map)
        if (r.tier == tier) out.push_back(r);
    return out;
}

std::vector<TensorResidency> ResidencyTracker::all() const {
    std::unique_lock<std::mutex> lk(m_mtx);
    std::vector<TensorResidency> out;
    out.reserve(m_map.size());
    for (auto& [id, r] : m_map) out.push_back(r);
    return out;
}

uint64_t ResidencyTracker::bytesInTier(MemoryTier tier) const {
    std::unique_lock<std::mutex> lk(m_mtx);
    uint64_t total = 0;
    for (auto& [id, r] : m_map)
        if (r.tier == tier) total += r.bytes;
    return total;
}

} // namespace Memory
} // namespace RawrXD
