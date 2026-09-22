#pragma once
#include "AgentSession.hpp"
#include "DeviceLeaseManager.hpp"

namespace rawrxd::swarm48 {

struct BatchPlan {
    DeviceId device{};
    ModelHandle model{};
    std::vector<AgentId> agents;
};

class ContinuousBatcher {
public:
    std::vector<BatchPlan> plan(
        std::span<AgentSession* const> sessions,
        const DeviceLeaseManager& leases,
        std::uint32_t max_batch_per_model) const;
};

} // namespace rawrxd::swarm48
