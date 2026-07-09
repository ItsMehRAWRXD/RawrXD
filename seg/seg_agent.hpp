#pragma once
#include "seg_graph.hpp"
#include "seg_memory.hpp"

namespace seg {

struct AgentConfig {
    bool enable_telemetry = true;
    bool enable_self_optimization = false;
};

class Agent {
public:
    void Initialize(const AgentConfig& cfg) { m_cfg = cfg; }

    void OnNodeStart(const Node& node);
    void OnNodeEnd(const Node& node);

private:
    AgentConfig m_cfg;
};

} // namespace seg
