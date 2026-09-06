#include "CommandEventJournal.h"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace RawrXD::Command {

static uint64_t nowMs() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

static const char* typeName(JournalEventType t) {
    switch (t) {
    case JournalEventType::SessionBound: return "session_bound";
    case JournalEventType::AgentStarted: return "agent_started";
    case JournalEventType::ToolCall: return "tool_call";
    case JournalEventType::ApprovalRequested: return "approval_requested";
    case JournalEventType::ApprovalResolved: return "approval_resolved";
    case JournalEventType::AgentStopped: return "agent_stopped";
    case JournalEventType::ModeSwitch: return "mode_switch";
    case JournalEventType::SteerMessage: return "steer_message";
    default: return "unknown";
    }
}

CommandEventJournal& CommandEventJournal::instance() {
    static CommandEventJournal j;
    return j;
}

std::string CommandEventJournal::pathForWorkspace(const std::string& root) const {
    return (fs::path(root) / ".rawrxd" / "command" / "journal" / "events.jsonl").string();
}

void CommandEventJournal::setWorkspaceRoot(const std::string& root) {
    journalPath_ = pathForWorkspace(root);
    fs::create_directories(fs::path(journalPath_).parent_path());
    lastSeq_ = 0;
    for (const auto& e : loadAll()) lastSeq_ = e.seq;
}

bool CommandEventJournal::append(JournalEventType type, const std::string& payload) {
    if (journalPath_.empty()) return false;
    fs::create_directories(fs::path(journalPath_).parent_path());
    const uint64_t seq = ++lastSeq_;
  std::ostringstream line;
    line << "{\"seq\":" << seq << ",\"ts\":" << nowMs()
         << ",\"type\":\"" << typeName(type) << "\",\"payload\":"
         << (payload.empty() ? "\"\"" : payload) << "}\n";
    std::ofstream out(journalPath_, std::ios::app);
    if (!out) return false;
    out << line.str();
    return true;
}

std::vector<JournalEvent> CommandEventJournal::loadAll() const {
    std::vector<JournalEvent> out;
    if (journalPath_.empty()) return out;
    std::ifstream in(journalPath_);
    if (!in) return out;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        JournalEvent e;
        auto p = line.find("\"seq\":");
        if (p != std::string::npos) e.seq = std::stoull(line.substr(p + 6));
        e.payload = line;
        out.push_back(e);
    }
    return out;
}

bool CommandEventJournal::resumeFromLast(std::string* outSummary) const {
    const auto events = loadAll();
    if (events.empty()) return false;
    if (outSummary) *outSummary = events.back().payload;
    return true;
}

}  // namespace RawrXD::Command
