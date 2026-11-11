#pragma once

#include "agent_state.hpp"
#include <string>
#include <cstdint>
#include <functional>

namespace rawrxd {
namespace agent {

struct AgentEventData {
    AgentEvent type;
    std::string source;       // Which agent generated the event
    std::string description;
    uint64_t timestamp_ms;
    void* context_data;       // Optional context pointer

    AgentEventData() : type(AgentEvent::UserRequest), timestamp_ms(0), context_data(nullptr) {}
    
    AgentEventData(AgentEvent t, const std::string& src, const std::string& desc)
        : type(t), source(src), description(desc), timestamp_ms(0), context_data(nullptr) {}
};

using AgentEventHandler = std::function<void(const AgentEventData&)>;

} // namespace agent
} // namespace rawrxd
