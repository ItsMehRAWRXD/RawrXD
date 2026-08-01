#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace rawrxd {
namespace agent {

struct AgentTraceEntry {
    uint64_t timestamp_ms;
    std::string agent_name;
    std::string action;
    std::string target;
    std::string result;
    uint64_t duration_ms;

    AgentTraceEntry() : timestamp_ms(0), duration_ms(0) {}
};

class AgentTrace {
public:
    AgentTrace();
    ~AgentTrace();

    void record(const AgentTraceEntry& entry);
    std::vector<AgentTraceEntry> getHistory() const;
    void clear();
    std::string toJson() const;

private:
    std::vector<AgentTraceEntry> history_;
};

} // namespace agent
} // namespace rawrxd
