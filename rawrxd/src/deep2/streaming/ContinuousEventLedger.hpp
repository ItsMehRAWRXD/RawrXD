#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <mutex>

namespace rawrxd::continuous {

enum class LedgerEventKind : uint8_t {
    StateChanged,
    Progress,
    TextDelta,
    ToolCall,
    ToolResult,
    FinalText,
    Completed,
    Error
};

struct LedgerEvent {
    uint64_t runId = 0;
    uint64_t sequence = 0;
    LedgerEventKind kind = LedgerEventKind::Progress;
    std::string payload;
};

class EventLedger final {
public:
    void append(const LedgerEvent& ev);
    std::vector<LedgerEvent> replaySince(uint64_t lastAckedSequence) const;
    uint64_t highestSequence() const;
    void clear();

private:
    mutable std::mutex mu_;
    std::vector<LedgerEvent> events_;
    uint64_t nextSeq_ = 1;
};

} // namespace rawrxd::continuous
