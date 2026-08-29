// =============================================================================
// AgentEventStream.hpp — Agentic coordination event channel (above frozen streamer)
// =============================================================================
#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace RawrXD::Agents {

enum class AgentEventType {
    Searching,
    Reading,
    Editing,
    Building,
    Testing,
    WorkAlreadyInProgress,
    JoinedExistingSearch,
    SharedResultReceived,
    LeaseAcquired,
    LeaseReleased,
    LeaseReclaimed,
    ConflictingWrite,
    ContinuingFromSharedResult,
    StaleRepoRejected,
    Info
};

struct AgentEvent {
    AgentEventType type = AgentEventType::Info;
    std::string message;
    uint64_t ownerSession = 0;
    uint64_t ownerAgent = 0;
    uint64_t sessionId = 0;
    uint64_t agentId = 0;
    std::string resource;
    std::string query;
    uint64_t matchCount = 0;
    uint64_t timestampMs = 0;
};

inline const char* agentEventTypeName(AgentEventType t) {
    switch (t) {
    case AgentEventType::Searching: return "SEARCHING";
    case AgentEventType::Reading: return "READING";
    case AgentEventType::Editing: return "EDITING";
    case AgentEventType::Building: return "BUILDING";
    case AgentEventType::Testing: return "TESTING";
    case AgentEventType::WorkAlreadyInProgress: return "WORK_ALREADY_IN_PROGRESS";
    case AgentEventType::JoinedExistingSearch: return "JOINED_EXISTING_SEARCH";
    case AgentEventType::SharedResultReceived: return "SHARED_RESULT_RECEIVED";
    case AgentEventType::LeaseAcquired: return "LEASE_ACQUIRED";
    case AgentEventType::LeaseReleased: return "LEASE_RELEASED";
    case AgentEventType::LeaseReclaimed: return "LEASE_RECLAIMED";
    case AgentEventType::ConflictingWrite: return "CONFLICTING_WRITE";
    case AgentEventType::ContinuingFromSharedResult: return "CONTINUING_FROM_SHARED_RESULT";
    case AgentEventType::StaleRepoRejected: return "STALE_REPO_REJECTED";
    case AgentEventType::Info: return "INFO";
    }
    return "INFO";
}

inline std::string formatAgentCoordLine(const AgentEvent& e) {
    std::ostringstream oss;
    const bool coord =
        e.type == AgentEventType::JoinedExistingSearch ||
        e.type == AgentEventType::WorkAlreadyInProgress ||
        e.type == AgentEventType::SharedResultReceived ||
        e.type == AgentEventType::ConflictingWrite ||
        e.type == AgentEventType::LeaseReclaimed ||
        e.type == AgentEventType::StaleRepoRejected;
    oss << (coord ? "[COORD] " : "[AGENT] ");
    if (!e.message.empty()) {
        oss << e.message;
    } else {
        oss << agentEventTypeName(e.type);
        if (!e.resource.empty()) oss << " " << e.resource;
        if (!e.query.empty()) oss << " query=" << e.query;
    }
    return oss.str();
}

class AgentEventStream {
public:
    using Sink = std::function<void(const AgentEvent&)>;

    static AgentEventStream& instance() {
        static AgentEventStream s;
        return s;
    }

    void setSink(Sink sink) {
        std::lock_guard<std::mutex> lock(m_mu);
        m_sink = std::move(sink);
    }

    void emit(AgentEvent e) {
        if (e.timestampMs == 0) {
            using namespace std::chrono;
            e.timestampMs = static_cast<uint64_t>(
                duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
        }
        std::lock_guard<std::mutex> lock(m_mu);
        m_history.push_back(e);
        while (m_history.size() > m_maxHistory) m_history.pop_front();
        if (m_sink) m_sink(e);
    }

    static std::string joinedExistingSearchBanner(uint64_t ownerSession,
                                                  uint64_t ownerAgent,
                                                  const std::string& resource,
                                                  const std::string& query) {
        std::ostringstream oss;
        oss << "[AGENT_COORD]\n"
            << "status=JOINED_EXISTING_SEARCH\n"
            << "owner_session=" << ownerSession << "\n"
            << "owner_agent=" << ownerAgent << "\n"
            << "resource=" << resource << "\n"
            << "query=" << query << "\n";
        return oss.str();
    }

private:
    mutable std::mutex m_mu;
    Sink m_sink;
    std::deque<AgentEvent> m_history;
    size_t m_maxHistory = 512;
};

} // namespace RawrXD::Agents
