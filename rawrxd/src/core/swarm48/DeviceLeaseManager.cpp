#include "rawrxd/swarm48/DeviceLeaseManager.hpp"

namespace rawrxd::swarm48 {
void DeviceLeaseManager::add_device(DeviceBudget budget) {
    std::lock_guard lock(mu_);
    devices_[budget.id] = State{std::move(budget), 0};
}

bool DeviceLeaseManager::acquire_decode(DeviceId id, std::uint32_t slots) {
    std::lock_guard lock(mu_);
    auto it = devices_.find(id);
    if (it == devices_.end() || !it->second.cfg.healthy) return false;
    if (slots > it->second.cfg.max_decode_slots - std::min(it->second.active, it->second.cfg.max_decode_slots)) return false;
    it->second.active += slots;
    return true;
}

void DeviceLeaseManager::set_health(DeviceId id, bool healthy) {
    std::lock_guard lock(mu_);
    auto it = devices_.find(id);
    if (it != devices_.end()) it->second.cfg.healthy = healthy;
}

void DeviceLeaseManager::release_decode(DeviceId id, std::uint32_t slots) {
    std::lock_guard lock(mu_);
    auto it = devices_.find(id);
    if (it == devices_.end()) return;
    it->second.active = slots >= it->second.active ? 0u : it->second.active - slots;
}

std::uint32_t DeviceLeaseManager::available_decode_slots(DeviceId id) const {
    std::lock_guard lock(mu_);
    auto it = devices_.find(id);
    if (it == devices_.end() || !it->second.cfg.healthy) return 0;
    return it->second.cfg.max_decode_slots - std::min(it->second.active, it->second.cfg.max_decode_slots);
}

std::optional<DeviceBudget> DeviceLeaseManager::budget(DeviceId id) const {
    std::lock_guard lock(mu_);
    auto it = devices_.find(id);
    if (it == devices_.end()) return std::nullopt;
    return it->second.cfg;
}
} // namespace rawrxd::swarm48
