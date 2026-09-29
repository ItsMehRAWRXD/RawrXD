// ============================================================================
// OSEvidence.hpp — Evidence Registry
// Every capability admission, resource allocation, and lifecycle transition
// produces evidence. This is the fail-closed record of what happened.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <chrono>
#include <mutex>

namespace RawrXD::OS {

// ---------------------------------------------------------------------------
// Evidence record — immutable once committed
// ---------------------------------------------------------------------------
struct EvidenceRecord {
    uint64_t seq = 0;               // Monotonic sequence
    uint64_t timestampNs = 0;       // When the evidence was recorded
    std::string entityId;           // Capability or resource ID
    std::string eventType;          // "admission", "allocation", "execution", "verification"
    std::string result;             // "PASS", "FAIL", "HOLD", "DENY"
    std::string reason;             // Human-readable
    std::string policyId;           // Which policy governed this
    std::string callerSurface;      // Which surface initiated
    std::string commitHash;         // Source commit (for reproducibility)
    std::unordered_map<std::string, std::string> fields;
};

// ---------------------------------------------------------------------------
// Evidence registry — the authoritative record of runtime truth
// This is the "Evidence Registry" from the Beaconism vision.
// ---------------------------------------------------------------------------
class OSEvidence {
public:
    static OSEvidence& Instance();

    // Record evidence (thread-safe, immutable after commit)
    uint64_t record(const std::string& entityId,
                    const std::string& eventType,
                    const std::string& result,
                    const std::string& reason,
                    const std::string& policyId = "",
                    const std::string& callerSurface = "");

    // Query evidence for an entity
    std::vector<EvidenceRecord> query(const std::string& entityId) const;

    // Query evidence by event type
    std::vector<EvidenceRecord> queryByType(const std::string& eventType) const;

    // Query evidence by result
    std::vector<EvidenceRecord> queryByResult(const std::string& result) const;

    // Get the most recent evidence for an entity
    EvidenceRecord latest(const std::string& entityId) const;

    // Count evidence by result
    uint64_t countByResult(const std::string& result) const;

    // Total evidence records
    uint64_t totalCount() const;

    // Export all evidence as JSONL
    std::string exportJsonl() const;

    // Export all evidence as CSV
    std::string exportCsv() const;

    // Clear all evidence (for testing only)
    void clear();

    // Current sequence
    uint64_t currentSeq() const { return seq_.load(); }

private:
    OSEvidence() = default;
    ~OSEvidence() = default;
    OSEvidence(const OSEvidence&) = delete;
    OSEvidence& operator=(const OSEvidence&) = delete;

    mutable std::mutex mutex_;
    std::atomic<uint64_t> seq_{0};
    std::vector<EvidenceRecord> records_;

    static uint64_t nowNs() noexcept {
        using namespace std::chrono;
        return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
    }
};

} // namespace RawrXD::OS