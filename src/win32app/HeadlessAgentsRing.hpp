#pragma once
/* R13 Headless agents ring — memory-only; no ReplayJournal. ≤99. */
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>

namespace HeadlessAgents {

enum : size_t { kCap = 256, kId = 48, kText = 512 };

struct Evt {
    uint8_t typeCode = 0;
    uint8_t success = 1;
    int32_t durationMs = 0;
    uint64_t timestampMs = 0;
    char sessionId[kId]{};
    char agentId[kId]{};
    char parentId[kId]{};
    char prompt[kText]{};
    char result[kText]{};
};

struct Stats {
    uint64_t totalEvents = 0;
    uint64_t agentStarted = 0;
    uint64_t agentCompleted = 0;
    uint64_t agentFailed = 0;
    uint64_t subAgentSpawned = 0;
    uint64_t chainSteps = 0;
    uint64_t toolInvocations = 0;
    uint64_t failuresDetected = 0;
};

inline const char* typeName(uint8_t c) {
    static const char* k[] = {"SessionEvent", "AgentStarted", "AgentCompleted",
                              "AgentFailed", "SubAgentSpawned", "ChainStepStarted",
                              "ToolInvoked", "FailureDetected"};
    return k[c < 8 ? c : 0];
}

inline void copyTrunc(char* d, size_t n, const std::string& s) {
    if (!d || n == 0) return;
    size_t m = s.size() < n - 1 ? s.size() : n - 1;
    std::memcpy(d, s.data(), m);
    d[m] = 0;
}

struct Ring {
    Evt buf[kCap]{};
    size_t head = 0;
    size_t count = 0;
    Stats stats{};
    std::mutex mu;

    void push(uint8_t type, const std::string& session, const std::string& agent,
              const std::string& parent, const std::string& prompt,
              const std::string& result, int32_t durMs, bool ok, uint64_t ts) {
        std::lock_guard<std::mutex> lk(mu);
        Evt& e = buf[head];
        e = Evt{};
        e.typeCode = type;
        e.success = ok ? 1 : 0;
        e.durationMs = durMs;
        e.timestampMs = ts;
        copyTrunc(e.sessionId, kId, session);
        copyTrunc(e.agentId, kId, agent);
        copyTrunc(e.parentId, kId, parent);
        copyTrunc(e.prompt, kText, prompt);
        copyTrunc(e.result, kText, result);
        head = (head + 1) % kCap;
        if (count < kCap) ++count;
        ++stats.totalEvents;
        if (type == 1) ++stats.agentStarted;
        else if (type == 2) ++stats.agentCompleted;
        else if (type == 3) ++stats.agentFailed;
        else if (type == 4) ++stats.subAgentSpawned;
        else if (type == 5) ++stats.chainSteps;
        else if (type == 6) ++stats.toolInvocations;
        else if (type == 7) ++stats.failuresDetected;
    }
};

} // namespace HeadlessAgents
