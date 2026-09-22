#pragma once
#include "Common.hpp"

namespace rawrxd::swarm48 {

struct DeviceBudget {
    DeviceId id{};
    std::string name;
    std::uint64_t vram_bytes{};
    std::uint64_t reserve_bytes{};
    std::uint32_t max_decode_slots{1};
    std::uint32_t max_logical_agents{1};
    bool healthy{true};
};

class DeviceLeaseManager {
public:
    void add_device(DeviceBudget budget);
    bool acquire_decode(DeviceId id, std::uint32_t slots);
    void release_decode(DeviceId id, std::uint32_t slots);
    void set_health(DeviceId id, bool healthy);
    std::uint32_t available_decode_slots(DeviceId id) const;
    std::optional<DeviceBudget> budget(DeviceId id) const;

private:
    struct State { DeviceBudget cfg; std::uint32_t active{}; };
    mutable std::mutex mu_;
    std::unordered_map<DeviceId, State> devices_;
};

} // namespace rawrxd::swarm48
