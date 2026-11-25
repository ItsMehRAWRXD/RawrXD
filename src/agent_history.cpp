// =============================================================================
// agent_history.cpp — AgentHistoryRecorder implementation (JSONL, replay).
// =============================================================================
#include "agent_history.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <random>

#include "subagent_core.h"   // SubAgentManager (replay)

namespace {

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof(b), "\\u%04x", c);
                    out += b;
                } else out += (char)c;
        }
    }
    return out;
}

std::string JsonUnescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\' || i + 1 >= s.size()) {
            out += s[i];
            continue;
        }
        const char c = s[++i];
        switch (c) {
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case 'u': {
                if (i + 4 < s.size()) {
                    const std::string hex = s.substr(i + 1, 4);
                    const unsigned code =
                        (unsigned)std::strtoul(hex.c_str(), nullptr, 16);
                    if (code < 0x80) out += (char)code;
                    i += 4;
                }
                break;
            }
            default: out += c; break;
        }
    }
    return out;
}

// Extract a string field from a flat JSON line ("key":"value").
std::string Field(const std::string& j, const std::string& key) {
    const std::string pat = "\"" + key + "\":\"";
    const size_t p = j.find(pat);
    if (p == std::string::npos) return {};
    const size_t s = p + pat.size();
    size_t e = s;
    while (e < j.size() && j[e] != '"') ++e;
    return JsonUnescape(j.substr(s, e - s));
}

int64_t FieldInt(const std::string& j, const std::string& key) {
    const std::string pat = "\"" + key + "\":";
    const size_t p = j.find(pat);
    if (p == std::string::npos) return 0;
    return std::strtoll(j.c_str() + p + pat.size(), nullptr, 10);
}

bool FieldBool(const std::string& j, const std::string& key) {
    const std::string pat = "\"" + key + "\":true";
    return j.find(pat) != std::string::npos;
}

}  // namespace

std::string AgentEvent::toJSON() const {
    std::string out = "{";
    out += "\"id\":" + std::to_string(id);
    out += ",\"eventType\":\"" + JsonEscape(eventType) + "\"";
    out += ",\"sessionId\":\"" + JsonEscape(sessionId) + "\"";
    out += ",\"timestampMs\":" + std::to_string(timestampMs);
    out += ",\"durationMs\":" + std::to_string(durationMs);
    out += ",\"agentId\":\"" + JsonEscape(agentId) + "\"";
    out += ",\"parentId\":\"" + JsonEscape(parentId) + "\"";
    out += ",\"description\":\"" + JsonEscape(description) + "\"";
    out += ",\"input\":\"" + JsonEscape(input) + "\"";
    out += ",\"output\":\"" + JsonEscape(output) + "\"";
    out += ",\"metadata\":\"" + JsonEscape(metadata) + "\"";
    out += success ? ",\"success\":true" : ",\"success\":false";
    out += ",\"errorMessage\":\"" + JsonEscape(errorMessage) + "\"";
    out += "}";
    return out;
}

AgentEvent AgentEvent::fromJSON(const std::string& j) {
    AgentEvent e;
    e.id = FieldInt(j, "id");
    e.eventType = Field(j, "eventType");
    e.sessionId = Field(j, "sessionId");
    e.timestampMs = FieldInt(j, "timestampMs");
    e.durationMs = (int)FieldInt(j, "durationMs");
    e.agentId = Field(j, "agentId");
    e.parentId = Field(j, "parentId");
    e.description = Field(j, "description");
    e.input = Field(j, "input");
    e.output = Field(j, "output");
    e.metadata = Field(j, "metadata");
    e.success = FieldBool(j, "success");
    e.errorMessage = Field(j, "errorMessage");
    return e;
}

AgentHistoryRecorder::AgentHistoryRecorder(const std::string& storageDir)
    : m_storageDir(storageDir), m_sessionId(generateSessionId()) {
    loadFromDisk();
}

AgentHistoryRecorder::~AgentHistoryRecorder() { flush(); }

std::string AgentHistoryRecorder::generateSessionId() const {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    const uint64_t v = gen();
    char buf[24];
    std::snprintf(buf, sizeof(buf), "sess_%016llx",
                  (unsigned long long)v);
    return buf;
}

std::string AgentHistoryRecorder::getLogFilePath() const {
    if (m_storageDir.empty()) return {};
    return m_storageDir + "/agent_history.jsonl";
}

int64_t AgentHistoryRecorder::nowMs() const {
    return (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string AgentHistoryRecorder::truncate(const std::string& s,
                                           size_t maxLen) const {
    if (s.size() <= maxLen) return s;
    return s.substr(0, maxLen) + "...[truncated]";
}

std::string AgentHistoryRecorder::escapeJsonValue(const std::string& s) const {
    return JsonEscape(s);
}
std::string AgentHistoryRecorder::unescapeJsonValue(const std::string& s) const {
    return JsonUnescape(s);
}

int64_t AgentHistoryRecorder::record(
    const std::string& eventType, const std::string& agentId,
    const std::string& parentId, const std::string& description,
    const std::string& input, const std::string& output, bool success,
    int durationMs, const std::string& errorMessage,
    const std::string& metadata) {
    std::lock_guard<std::mutex> lock(m_mutex);
    AgentEvent e;
    e.id = m_nextId++;
    e.eventType = eventType;
    e.sessionId = m_sessionId;
    e.timestampMs = nowMs();
    e.durationMs = durationMs;
    e.agentId = agentId;
    e.parentId = parentId;
    e.description = description;
    e.input = truncate(input, m_maxPayloadBytes);
    e.output = truncate(output, m_maxPayloadBytes);
    e.metadata = metadata;
    e.success = success;
    e.errorMessage = errorMessage;
    m_events.push_back(e);
    logDebug("record " + eventType + " id=" + std::to_string(e.id));
    return e.id;
}

int64_t AgentHistoryRecorder::recordAgentSpawn(const std::string& agentId,
                                               const std::string& parentId,
                                               const std::string& description,
                                               const std::string& prompt) {
    return record("agent_spawn", agentId, parentId, description, prompt, "",
                  true);
}
int64_t AgentHistoryRecorder::recordAgentComplete(const std::string& agentId,
                                                  const std::string& result,
                                                  int durationMs) {
    return record("agent_complete", agentId, "", "completed", "", result,
                  true, durationMs);
}
int64_t AgentHistoryRecorder::recordAgentFail(const std::string& agentId,
                                              const std::string& error,
                                              int durationMs) {
    return record("agent_fail", agentId, "", "failed", "", "", false,
                  durationMs, error);
}
int64_t AgentHistoryRecorder::recordAgentCancel(const std::string& agentId) {
    return record("agent_cancel", agentId, "", "cancelled", "", "", false, 0,
                  "cancelled");
}
int64_t AgentHistoryRecorder::recordToolInvoke(const std::string& agentId,
                                               const std::string& toolName,
                                               const std::string& input) {
    return record("tool_invoke", agentId, "", toolName, input, "", true, 0,
                  "", toolName);
}
int64_t AgentHistoryRecorder::recordToolResult(const std::string& agentId,
                                               const std::string& toolName,
                                               const std::string& result,
                                               bool success) {
    return record("tool_result", agentId, "", toolName, "", result, success);
}
int64_t AgentHistoryRecorder::recordChainStart(const std::string& parentId,
                                               int stepCount) {
    return record("chain_start", "", parentId, "chain", "", "", true, 0, "",
                  std::to_string(stepCount));
}
int64_t AgentHistoryRecorder::recordChainStep(const std::string& parentId,
                                              int stepIndex,
                                              const std::string& agentId,
                                              const std::string& result,
                                              bool success, int durationMs) {
    return record("chain_step", agentId, parentId,
                  "step " + std::to_string(stepIndex), "", result, success,
                  durationMs);
}
int64_t AgentHistoryRecorder::recordChainComplete(
    const std::string& parentId, const std::string& result, int stepCount,
    int totalDurationMs) {
    return record("chain_complete", "", parentId, "chain complete", "",
                  result, true, totalDurationMs,
                  std::to_string(stepCount));
}
int64_t AgentHistoryRecorder::recordSwarmStart(const std::string& parentId,
                                               int taskCount,
                                               const std::string& strategy) {
    return record("swarm_start", "", parentId, "swarm", "", "", true, 0, "",
                  strategy + ":" + std::to_string(taskCount));
}
int64_t AgentHistoryRecorder::recordSwarmTask(const std::string& parentId,
                                              const std::string& taskId,
                                              const std::string& agentId,
                                              const std::string& result,
                                              bool success, int durationMs) {
    return record("swarm_task", agentId, parentId, taskId, "", result,
                  success, durationMs);
}
int64_t AgentHistoryRecorder::recordSwarmComplete(
    const std::string& parentId, const std::string& mergedResult,
    int taskCount, const std::string& strategy, int totalDurationMs) {
    return record("swarm_complete", "", parentId, "swarm complete", "",
                  mergedResult, true, totalDurationMs,
                  strategy + ":" + std::to_string(taskCount));
}
int64_t AgentHistoryRecorder::recordChatRequest(const std::string& message) {
    return record("chat_request", "", "", "chat", message, "", true);
}
int64_t AgentHistoryRecorder::recordChatResponse(const std::string& response,
                                                 int durationMs) {
    return record("chat_response", "", "", "chat", "", response, true,
                  durationMs);
}
int64_t AgentHistoryRecorder::recordTodoUpdate(int todoId,
                                               const std::string& title,
                                               const std::string& status) {
    return record("todo_update", "", "", title, status, "", true, 0, "",
                  std::to_string(todoId));
}

std::vector<AgentEvent> AgentHistoryRecorder::query(
    const HistoryQuery& q) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<AgentEvent> out;
    int skipped = 0;
    for (const auto& e : m_events) {
        if (!q.sessionId.empty() && e.sessionId != q.sessionId) continue;
        if (!q.agentId.empty() && e.agentId != q.agentId) continue;
        if (!q.eventType.empty() && e.eventType != q.eventType) continue;
        if (!q.parentId.empty() && e.parentId != q.parentId) continue;
        if (q.afterTimestamp && e.timestampMs < q.afterTimestamp) continue;
        if (q.beforeTimestamp && e.timestampMs > q.beforeTimestamp) continue;
        if (q.successOnly && !e.success) continue;
        if (skipped < q.offset) {
            ++skipped;
            continue;
        }
        out.push_back(e);
        if ((int)out.size() >= q.limit) break;
    }
    return out;
}

std::vector<AgentEvent> AgentHistoryRecorder::getAgentTimeline(
    const std::string& agentId) const {
    HistoryQuery q;
    q.agentId = agentId;
    q.limit = 1000;
    return query(q);
}

std::vector<AgentEvent> AgentHistoryRecorder::getSessionTimeline(
    const std::string& sessionId) const {
    HistoryQuery q;
    q.sessionId = sessionId;
    q.limit = 100000;
    return query(q);
}

std::vector<AgentEvent> AgentHistoryRecorder::getEventsByType(
    const std::string& eventType, int limit) const {
    HistoryQuery q;
    q.eventType = eventType;
    q.limit = limit;
    return query(q);
}

std::vector<AgentEvent> AgentHistoryRecorder::getChainEvents(
    const std::string& parentId) const {
    HistoryQuery q;
    q.parentId = parentId;
    q.eventType = "chain";
    q.limit = 100000;
    // chain events use several types; collect them all for the parent.
    std::vector<AgentEvent> out;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& e : m_events) {
        if (e.parentId == parentId &&
            (e.eventType.rfind("chain", 0) == 0 ||
             e.eventType.rfind("swarm", 0) == 0))
            out.push_back(e);
    }
    return out;
}

std::vector<AgentEvent> AgentHistoryRecorder::getSwarmEvents(
    const std::string& parentId) const {
    std::vector<AgentEvent> out;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& e : m_events) {
        if (e.parentId == parentId && e.eventType.rfind("swarm", 0) == 0)
            out.push_back(e);
    }
    return out;
}

std::vector<AgentEvent> AgentHistoryRecorder::allEvents() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_events;
}

size_t AgentHistoryRecorder::eventCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_events.size();
}

std::string AgentHistoryRecorder::toJSON(
    const std::vector<AgentEvent>& events) const {
    std::string out = "[";
    for (size_t i = 0; i < events.size(); ++i) {
        if (i) out += ",";
        out += events[i].toJSON();
    }
    out += "]";
    return out;
}

std::string AgentHistoryRecorder::getStatsSummary() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t ok = 0;
    for (const auto& e : m_events)
        if (e.success) ++ok;
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "{\"events\":%zu,\"success\":%zu,\"failed\":%zu}",
                  m_events.size(), ok, m_events.size() - ok);
    return buf;
}

ReplayResult AgentHistoryRecorder::replay(const ReplayRequest& req,
                                          SubAgentManager* mgr) {
    ReplayResult r;
    r.success = false;
    r.eventsReplayed = 0;
    if (!mgr) {
        r.result = "No SubAgentManager available";
        return r;
    }
    std::vector<AgentEvent> events;
    if (!req.originalAgentId.empty())
        events = getAgentTimeline(req.originalAgentId);
    else if (!req.originalSessionId.empty())
        events = getSessionTimeline(req.originalSessionId);
    if (events.empty()) {
        r.result = "No events to replay";
        return r;
    }
    if (req.dryRun) {
        r.success = true;
        r.eventsReplayed = (int)events.size();
        r.result = "dry-run: " + std::to_string(events.size()) +
                   " events would replay";
        return r;
    }
    // Re-execute chain steps through the manager (real execution).
    for (const auto& e : events) {
        if (e.eventType == "chain_step") {
            const std::string id = mgr->spawnSubAgent(e.parentId,
                                                      e.description, e.input);
            mgr->waitForSubAgent(id, 60000);
            r.replayEvents.push_back(e);
            ++r.eventsReplayed;
        }
    }
    r.success = true;
    r.result = "replayed " + std::to_string(r.eventsReplayed) + " events";
    return r;
}

void AgentHistoryRecorder::flush() {
    std::lock_guard<std::mutex> lock(m_mutex);
    const std::string path = getLogFilePath();
    if (path.empty()) return;
    std::filesystem::create_directories(
        std::filesystem::path(path).parent_path());
    std::ofstream out(path, std::ios::app);
    if (!out) {
        logError("cannot open history log");
        return;
    }
    for (const auto& e : m_events) out << e.toJSON() << "\n";
    m_events.clear();
    m_nextId = 1;
}

void AgentHistoryRecorder::loadFromDisk() {
    std::lock_guard<std::mutex> lock(m_mutex);
    const std::string path = getLogFilePath();
    if (path.empty()) return;
    std::ifstream in(path);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        m_events.push_back(AgentEvent::fromJSON(line));
    }
    int64_t maxId = 0;
    for (const auto& e : m_events) maxId = std::max(maxId, e.id);
    m_nextId = maxId + 1;
}

void AgentHistoryRecorder::purgeExpired() {
    std::lock_guard<std::mutex> lock(m_mutex);
    const int64_t cutoff = nowMs() - (int64_t)m_retentionDays * 86400000LL;
    m_events.erase(std::remove_if(m_events.begin(), m_events.end(),
                                  [cutoff](const AgentEvent& e) {
                                      return e.timestampMs < cutoff;
                                  }),
                   m_events.end());
}

void AgentHistoryRecorder::clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.clear();
    m_nextId = 1;
}