#include "seg_agent.hpp"

namespace seg {

void Agent::OnNodeStart(const Node& node) {
    if (!m_cfg.enable_telemetry) return;
    // Example: log phase start by node kind
    // Telemetry_Log(0x3000 + static_cast<uint8_t>(node.kind), 0, 0);
}

void Agent::OnNodeEnd(const Node& node) {
    if (!m_cfg.enable_telemetry) return;
    // Telemetry_Log(0x4000 + static_cast<uint8_t>(node.kind), 0, 0);
}

} // namespace seg
