#pragma once
/* R13 JSON builders for Headless agents HTTP. ≤99. */
#include "HeadlessAgentsRing.hpp"
#include <sstream>
#include <string>
#include <vector>

namespace HeadlessAgents {

template <typename EscFn>
inline std::string buildHistoryJson(const Ring& ring, const std::string& session,
                                    const std::string& agentFilt,
                                    const std::string& typeFilt,
                                    const std::string& sessFilt, int limit,
                                    EscFn esc) {
    std::vector<Evt> snap;
    Stats st{};
    {
        std::lock_guard<std::mutex> lk(const_cast<Ring&>(ring).mu);
        st = ring.stats;
        snap.reserve(ring.count);
        size_t start = (ring.head + kCap - ring.count) % kCap;
        for (size_t i = 0; i < ring.count; ++i)
            snap.push_back(ring.buf[(start + i) % kCap]);
    }
    std::vector<const Evt*> filtered;
    for (const auto& e : snap) {
        if (!agentFilt.empty() && agentFilt != e.agentId) continue;
        if (!typeFilt.empty() && typeFilt != typeName(e.typeCode)) continue;
        if (!sessFilt.empty() && sessFilt != e.sessionId) continue;
        filtered.push_back(&e);
    }
    if ((int)filtered.size() > limit && limit > 0)
        filtered.erase(filtered.begin(),
                       filtered.begin() + (filtered.size() - (size_t)limit));
    std::ostringstream j;
    j << "{\"events\":[";
    for (size_t i = 0; i < filtered.size(); ++i) {
        const Evt* e = filtered[i];
        if (i) j << ",";
        const char* desc = e->prompt[0] ? e->prompt : e->result;
        j << "{\"id\":" << i << ",\"eventType\":\"" << esc(typeName(e->typeCode))
          << "\",\"sessionId\":\"" << esc(e->sessionId)
          << "\",\"timestampMs\":" << e->timestampMs
          << ",\"durationMs\":" << e->durationMs << ",\"agentId\":\""
          << esc(e->agentId) << "\",\"parentId\":\"" << esc(e->parentId)
          << "\",\"description\":\"" << esc(desc) << "\",\"input\":\""
          << esc(e->prompt) << "\",\"output\":\"" << esc(e->result)
          << "\",\"metadata\":\"\",\"success\":"
          << (e->success ? "true" : "false") << ",\"errorMessage\":\""
          << (e->success ? "" : esc(e->result)) << "\"}";
    }
    j << "],\"stats\":{\"totalEvents\":" << st.totalEvents << ",\"sessionId\":\""
      << esc(session) << "\",\"successCount\":" << st.agentCompleted
      << ",\"failCount\":" << st.agentFailed
      << ",\"eventTypes\":{\"AgentStarted\":" << st.agentStarted
      << ",\"AgentCompleted\":" << st.agentCompleted
      << ",\"AgentFailed\":" << st.agentFailed
      << ",\"SubAgentSpawned\":" << st.subAgentSpawned
      << ",\"ChainSteps\":" << st.chainSteps
      << ",\"ToolInvocations\":" << st.toolInvocations
      << ",\"FailuresDetected\":" << st.failuresDetected << "}}}";
    return j.str();
}

template <typename EscFn>
inline std::string buildStatusJson(const Ring& ring, uint64_t failDet,
                                   uint64_t failRetry, EscFn esc) {
    Stats st{};
    {
        std::lock_guard<std::mutex> lk(const_cast<Ring&>(ring).mu);
        st = ring.stats;
    }
    (void)esc;
    std::ostringstream j;
    j << "{\"agents\":{\"active\":" << st.agentStarted << ",\"completed\":"
      << st.agentCompleted << ",\"failed\":" << st.agentFailed
      << ",\"subagents\":" << st.subAgentSpawned << "},\"failures\":{\"total\":"
      << failDet << ",\"totalRequests\":" << st.totalEvents
      << ",\"totalRetries\":" << failRetry
      << ",\"successAfterRetry\":0,\"retriesDeclined\":0,\"byType\":{},"
         "\"retrySuccessRate\":0.0},\"intelligence\":{}}";
    return j.str();
}

} // namespace HeadlessAgents
