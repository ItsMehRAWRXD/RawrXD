#pragma once
#include "AgentSession.hpp"

namespace rawrxd::swarm48 {

struct TeamDefinition {
    TeamId id{};
    std::string name;
    AgentId synthesizer{};
    std::vector<AgentId> workers;
};

class TeamCoordinator {
public:
    void define(TeamDefinition team);
    std::optional<AgentId> synthesizer_if_ready(TeamId team, const std::unordered_map<AgentId, AgentSession>& sessions) const;
    std::vector<AgentId> team_workers(TeamId team) const;

private:
    std::unordered_map<TeamId, TeamDefinition> teams_;
};

} // namespace rawrxd::swarm48
