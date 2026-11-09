#include "AgentSession.hpp"
#include <fstream>
#include <cstdlib>

namespace {
uint64_t FieldNum(const std::string& line, const char* key) {
    auto p = line.find(key);
    if (p == std::string::npos) return 0;
    p = line.find(':', p);
    if (p == std::string::npos) return 0;
    return std::strtoull(line.c_str() + p + 1, nullptr, 10);
}
std::string FieldStr(const std::string& line) {
    auto a = line.find("\"path\":\"");
    if (a == std::string::npos) return {};
    auto b = line.find('"', a + 8);
    if (b == std::string::npos) return {};
    return line.substr(a + 8, b - (a + 8));
}
}  // namespace

bool AgentSessionRestore(const std::string& dir, AgentSessionNote* out) {
    std::ifstream in(dir + "\\session.jsonl");
    if (!in) return false;
    AgentSessionAbandonLive();
    std::string line;
    uint64_t session = 0;
    int cancelled = 0;
    while (std::getline(in, line)) {
        if (line.find("SessionStarted") != std::string::npos) {
            session = FieldNum(line, "\"session\"");
            AgentSessionLoadIds(session, FieldNum(line, "\"task\""), 0);
            cancelled = 0;
        } else if (line.find("FileChanged") != std::string::npos &&
                   FieldNum(line, "\"session\"") == session) {
            AgentSessionLoadRow(FieldStr(line), FieldNum(line, "\"before\""),
                                FieldNum(line, "\"after\""));
        } else if (line.find("SessionCancelled") != std::string::npos) {
            cancelled = 1;
            AgentSessionMarkCancelled();
        }
    }
    if (!session) return false;
    if (out) {
        out->sessionId = session;
        out->taskId = AgentSessionTaskId();
        out->filesChanged = AgentSessionFilesChanged();
        out->terminals = 0;
        out->cancelled = cancelled;
    }
    return true;
}

int AgentSessionAdmit(const std::string& body, std::string* json) {
    if (body.find("\"restore\":true") != std::string::npos) {
        AgentSessionNote note{};
        if (!AgentSessionRestore("agent_sessions", &note)) {
            if (json) *json = "{\"error\":\"no_session\"}";
            return 404;
        }
        if (json) *json = "{\"restored\":true,\"session\":" + std::to_string(note.sessionId) +
                          ",\"files_changed\":" + std::to_string(note.filesChanged) +
                          ",\"terminals\":0,\"cancelled\":" + std::to_string(note.cancelled) + "}";
        return 200;
    }
    if (body.find("\"cancel\":true") != std::string::npos) {
        AgentSessionCancel();
        if (json) *json = "{" + AgentSessionCountersJson() + "}";
        return 200;
    }
    AgentSessionBegin("agent_sessions", nullptr, nullptr);
    return 0;
}
