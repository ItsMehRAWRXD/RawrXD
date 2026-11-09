#include "AgentSession.hpp"
#include <atomic>
#include <fstream>
#include <vector>
#include <windows.h>

namespace {
struct Row { std::string path; uint64_t first = 0; uint64_t last = 0; std::string prior, next; };
std::vector<Row>& Rows() { static std::vector<Row> rows; return rows; }
std::atomic<int>& Cancel() { static std::atomic<int> v{0}; return v; }
std::atomic<int>& Terms() { static std::atomic<int> v{0}; return v; }
uint64_t& Session() { static uint64_t v = 0; return v; }
uint64_t& Task() { static uint64_t v = 0; return v; }
std::string& Dir() { static std::string v; return v; }
uint64_t Fnv(const std::string& s) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) { h ^= c; h *= 1099511628211ull; }
    return h;
}
void Append(const std::string& line) {
    if (Dir().empty()) return;
    std::ofstream out(Dir() + "\\session.jsonl", std::ios::app);
    out << line << "\n";
}
std::string Esc(const std::string& s) {
    std::string o;
    for (char c : s) o.push_back((c == '\\' || c == '"') ? '/' : c);
    return o;
}
}

int AgentSessionFilesChanged() {
    int n = 0;
    for (const auto& r : Rows()) if (r.first != r.last) ++n;
    return n;
}
int AgentSessionTerminals() { int n = Terms().load(); return n < 0 ? 0 : n; }
bool AgentSessionCancelled() { return Cancel().load() != 0; }
void AgentSessionMarkCancelled() { Cancel().store(1); }
uint64_t AgentSessionTaskId() { return Task(); }

bool AgentSessionBegin(const std::string& dir, uint64_t* sessionId, uint64_t* taskId) {
    Rows().clear(); Cancel().store(0); Terms().store(0); Dir() = dir;
    CreateDirectoryA(dir.c_str(), nullptr);
    Session() = GetTickCount64();
    Task() = Session() ^ 0x9e3779b97f4a7c15ull;
    if (sessionId) *sessionId = Session();
    if (taskId) *taskId = Task();
    Append("{\"kind\":\"SessionStarted\",\"session\":" + std::to_string(Session()) +
           ",\"task\":" + std::to_string(Task()) + "}");
    return true;
}
void AgentSessionCancel() {
    Cancel().store(1);
    Append("{\"kind\":\"SessionCancelled\",\"session\":" + std::to_string(Session()) + "}");
}
bool AgentSessionNoteWrite(const std::string& path, const std::string& before,
                           const std::string& after) {
    uint64_t b = Fnv(before), a = Fnv(after);
    Row* row = nullptr;
    for (auto& r : Rows()) if (r.path == path) row = &r;
    if (!row) { Rows().push_back({path, b, a, before, after}); row = &Rows().back(); }
    else { row->last = a; row->next = after; }
    Append("{\"kind\":\"FileChanged\",\"session\":" + std::to_string(Session()) +
           ",\"path\":\"" + Esc(path) + "\",\"before\":" + std::to_string(row->first) +
           ",\"after\":" + std::to_string(row->last) + "}");
    return true;
}
void AgentSessionNoteTerminal(uint64_t pid, int live) {
    if (live) Terms().fetch_add(1); else Terms().fetch_sub(1);
    Append("{\"kind\":\"Terminal\",\"session\":" + std::to_string(Session()) +
           ",\"pid\":" + std::to_string(pid) + ",\"live\":" + std::to_string(live) + "}");
}
std::string AgentSessionCountersJson() {
    return "\"session\":" + std::to_string(Session()) + ",\"task\":" + std::to_string(Task()) +
           ",\"files_changed\":" + std::to_string(AgentSessionFilesChanged()) +
           ",\"terminals\":" + std::to_string(AgentSessionTerminals()) +
           ",\"cancelled\":" + std::to_string(Cancel().load());
}
void AgentSessionAbandonLive() {
    Rows().clear(); Cancel().store(0); Terms().store(0); Session() = 0; Task() = 0;
}
void AgentSessionLoadIds(uint64_t session, uint64_t task, int cancelled) {
    Rows().clear(); Terms().store(0); Session() = session; Task() = task;
    Cancel().store(cancelled);
}
void AgentSessionLoadRow(const std::string& path, uint64_t first, uint64_t last) {
    for (auto& r : Rows()) if (r.path == path) { r.last = last; return; }
    Rows().push_back({path, first, last});
}
std::string AgentSessionReviewFirst() {
    for (const auto& r : Rows()) if (r.first != r.last)
        return "---\n" + r.prior + "\n+++\n" + r.next;
    return {};
}
