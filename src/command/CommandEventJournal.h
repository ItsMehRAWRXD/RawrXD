#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace RawrXD::Command {

enum class JournalEventType : uint8_t {
    SessionBound,
    AgentStarted,
    ToolCall,
    ApprovalRequested,
    ApprovalResolved,
    AgentStopped,
    ModeSwitch,
    SteerMessage,
};

struct JournalEvent {
    uint64_t seq = 0;
    uint64_t tsMs = 0;
    JournalEventType type = JournalEventType::SessionBound;
    std::string payload;
};

class CommandEventJournal {
public:
    static CommandEventJournal& instance();

    void setWorkspaceRoot(const std::string& root);
    bool append(JournalEventType type, const std::string& payload);
    std::vector<JournalEvent> loadAll() const;
    uint64_t lastSeq() const { return lastSeq_; }
    bool resumeFromLast(std::string* outSummary) const;

private:
    std::string journalPath_;
    uint64_t lastSeq_ = 0;
    std::string pathForWorkspace(const std::string& root) const;
};

}  // namespace RawrXD::Command
