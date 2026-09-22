#include "rawrxd/swarm48/ContinuousBatcher.hpp"
#include "rawrxd/swarm48/DeviceLeaseManager.hpp"
#include <map>
#include <tuple>

namespace rawrxd::swarm48 {

std::vector<BatchPlan> ContinuousBatcher::plan(
    std::span<AgentSession* const> sessions,
    const DeviceLeaseManager& leases,
    std::uint32_t max_batch_per_model) const {

    using Key = std::pair<DeviceId, ModelHandle>;
    std::map<Key, std::vector<AgentSession*>> groups;
    for (auto* s : sessions) {
        if (!s || s->state != AgentState::runnable || !s->model) continue;
        groups[{s->spec.device, s->model->handle}].push_back(s);
    }

    std::vector<BatchPlan> out;
    std::unordered_map<DeviceId, std::uint32_t> remaining;
    for (auto& [key, group] : groups) {
        auto [dev, model] = key;
        auto [it, inserted] = remaining.emplace(dev, leases.available_decode_slots(dev));
        if (it->second == 0) continue;
        std::stable_sort(group.begin(), group.end(), [](const AgentSession* a, const AgentSession* b) {
            if (a->spec.priority != b->spec.priority) return a->spec.priority > b->spec.priority;
            if (a->last_run_us != b->last_run_us) return a->last_run_us < b->last_run_us;
            return a->enqueued_us < b->enqueued_us;
        });
        const auto take = std::min<std::size_t>({group.size(), max_batch_per_model, it->second});
        if (!take) continue;
        BatchPlan p{dev, model, {}};
        p.agents.reserve(take);
        for (std::size_t i = 0; i < take; ++i) p.agents.push_back(group[i]->spec.id);
        it->second -= static_cast<std::uint32_t>(take);
        out.push_back(std::move(p));
    }
    return out;
}

} // namespace rawrxd::swarm48
