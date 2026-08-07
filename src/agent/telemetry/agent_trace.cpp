#include "agent_trace.hpp"
#include <sstream>
#include <chrono>

namespace rawrxd {
namespace agent {

AgentTrace::AgentTrace() = default;
AgentTrace::~AgentTrace() = default;

void AgentTrace::record(const AgentTraceEntry& entry) {
    AgentTraceEntry timed_entry = entry;
    if (timed_entry.timestamp_ms == 0) {
        timed_entry.timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    history_.push_back(timed_entry);
}

std::vector<AgentTraceEntry> AgentTrace::getHistory() const {
    return history_;
}

void AgentTrace::clear() {
    history_.clear();
}

std::string AgentTrace::toJson() const {
    std::ostringstream json;
    json << "{\"traces\":[";
    for (size_t i = 0; i < history_.size(); ++i) {
        if (i > 0) json << ",";
        json << "{"
             << "\"timestamp\":" << history_[i].timestamp_ms << ","
             << "\"agent\":\"" << history_[i].agent_name << "\","
             << "\"action\":\"" << history_[i].action << "\","
             << "\"target\":\"" << history_[i].target << "\","
             << "\"result\":\"" << history_[i].result << "\","
             << "\"duration_ms\":" << history_[i].duration_ms
             << "}";
    }
    json << "]}";
    return json.str();
}

} // namespace agent
} // namespace rawrxd
