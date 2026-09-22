#include "rawrxd/swarm48/TeamCoordinator.hpp"

namespace rawrxd::swarm48 {
void TeamCoordinator::define(TeamDefinition team) { teams_[team.id] = std::move(team); }

std::optional<AgentId> TeamCoordinator::synthesizer_if_ready(
    TeamId team, const std::unordered_map<AgentId, AgentSession>& sessions) const {
    auto it = teams_.find(team);
    if (it == teams_.end()) return std::nullopt;
    for (auto id : it->second.workers) {
        auto s = sessions.find(id);
        if (s == sessions.end()) return std::nullopt;
        if (s->second.state != AgentState::completed && s->second.state != AgentState::failed && s->second.state != AgentState::cancelled)
            return std::nullopt;
    }
    return it->second.synthesizer;
}

std::vector<AgentId> TeamCoordinator::team_workers(TeamId team) const {
    auto it = teams_.find(team);
    return it == teams_.end() ? std::vector<AgentId>{} : it->second.workers;
}
} // namespace rawrxd::swarm48
