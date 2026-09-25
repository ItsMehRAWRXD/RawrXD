#pragma once
#include "ContinuousExecution.hpp"
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd::continuous {

// RAWRXD_CONTINUOUS_STREAM_REALITY_001
// Per-run durable append-only event ledger.
// When the UI reconnects, it replays events from its last ACK point.
// No polling timer required.
class EventLedger final {
public:
    struct Record {
        uint64_t sequence{};
        uint64_t runId{};
        EventKind kind{EventKind::Progress};
        std::string text;
        std::string payload;
        uint64_t tokenIndex{};
        uint64_t workEpoch{};
    };

    // Append an event. sequence is monotonically increasing per run.
    void append(uint64_t runId, const Event& ev);

    // Query all records for a run.
    std::vector<Record> query(uint64_t runId) const;

    // Replay events from a specific sequence (exclusive).
    // Returns records where record.sequence > fromSequence.
    std::vector<Record> replay(uint64_t runId, uint64_t fromSequence) const;

    // Latest sequence for a run (0 if none).
    uint64_t latestSequence(uint64_t runId) const;

    // Trim records for a run up to (and including) a sequence.
    void trim(uint64_t runId, uint64_t upToSequence);

    // Remove all records for a run.
    void drop(uint64_t runId);

    // Total records across all runs.
    size_t totalRecords() const;

private:
    mutable std::mutex mu_;
    struct RunLedger {
        std::vector<Record> records;
        uint64_t nextSequence{1};
    };
    std::unordered_map<uint64_t, RunLedger> runs_;
};

} // namespace rawrxd::continuous
