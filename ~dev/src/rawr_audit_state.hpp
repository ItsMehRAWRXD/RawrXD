#pragma once
// ============================================================================
// rawr_audit_state.hpp — RAWR_AUDIT_STATE_001
// Durable native audit ledger. The runtime — not the model — owns coverage
// counters and completion authority. The model records candidates and marks
// files reviewed through tools; the ledger persists every transition and
// refuses completion until deterministic coverage is satisfied.
// ============================================================================
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "rawr_stub_scan.hpp"

namespace rawrxd {
namespace agent {

enum class CandidateType : uint8_t {
    Todo          = 0,
    EmptyImpl     = 1,
    FakeSuccess   = 2,
    DisabledPath  = 3,
    Unreachable   = 4,
    StubApi       = 5,
    Other         = 6,
};

inline const char* candidateTypeName(CandidateType t) {
    switch (t) {
        case CandidateType::Todo:         return "todo_fixme";
        case CandidateType::EmptyImpl:    return "empty_implementation";
        case CandidateType::FakeSuccess:  return "fake_success_path";
        case CandidateType::DisabledPath: return "disabled_production_path";
        case CandidateType::Unreachable:  return "unreachable_feature";
        case CandidateType::StubApi:      return "stub_api";
        case CandidateType::Other:       return "other";
    }
    return "other";
}

struct AuditCandidate {
    uint64_t                id = 0;
    std::string             file;
    uint32_t                line = 0;
    CandidateType           type = CandidateType::Other;
    ScanKind                scanKind = ScanKind::StubComment;  // RAWR_STUB_SCAN_001 origin
    std::string             evidence;
    std::string             reasoning;

    // Review state — RAWR_AUDIT_STATE_001 review contract.
    bool                    reviewed = false;
    std::string             verdict;      // confirmed | false_positive | needs_runtime_proof
    std::string             reviewNote;
};

struct AuditCounters {
    uint64_t filesTotal       = 0;
    uint64_t filesEnumerated  = 0;
    uint64_t filesReviewed    = 0;
    uint64_t filesExcluded    = 0;
    uint64_t filesScanned     = 0;      // RAWR_STUB_SCAN_001
    bool     sourceScanComplete = false; // RAWR_STUB_SCAN_001
    uint64_t candidatesTotal     = 0;
    uint64_t candidatesReviewed  = 0;
    uint64_t candidatesPending  = 0;
    uint64_t confirmedDefects   = 0;
    uint64_t falsePositives     = 0;
    uint64_t needsRuntimeProof  = 0;
    uint64_t toolFailures       = 0;
    uint64_t modelFallbacks     = 0;
};

// ============================================================================
// AuditLedger — durable state + deterministic coverage authority.
// ============================================================================
class AuditLedger {
public:
    // Opens (or resumes) the JSONL ledger under <workspace>/.rawr/.
    explicit AuditLedger(std::filesystem::path workspaceRoot);

    // Deterministic source enumeration with ignore/exclusion policy.
    // Returns the number of files enumerated. Idempotent.
    uint64_t enumerateSources();

    // RAWR_STUB_SCAN_001: scan every enumerated file for candidates.
    // Populates the candidate ledger; sets sourceScanComplete. Idempotent.
    bool runSourceScan();

    // Model-driven state transitions (invoked by audit.* tools only).
    uint64_t addCandidate(const std::string& file, uint32_t line,
                          CandidateType type, const std::string& evidence,
                          const std::string& reasoning);
    uint64_t addScanCandidate(const ScanCandidate& sc);
    bool reviewCandidate(uint64_t id, const std::string& verdict,
                         const std::string& note);
    bool markFilesReviewed(const std::vector<std::string>& files);

    // Candidate access for audit.candidate.read / audit.candidates tools.
    std::vector<AuditCandidate> pendingCandidates(uint32_t limit) const;
    size_t candidateCount() const;

    void countToolFailure()   { std::lock_guard<std::mutex> g(mu_); counters_.toolFailures++; persistLocked(); }
    void countModelFallback(){ std::lock_guard<std::mutex> g(mu_); counters_.modelFallbacks++; persistLocked(); }

    AuditCounters counters() const {
        std::lock_guard<std::mutex> g(mu_);
        AuditCounters c = counters_;
        c.candidatesTotal    = candidates_.size();
        c.candidatesReviewed = 0;
        c.confirmedDefects   = 0;
        c.falsePositives     = 0;
        c.needsRuntimeProof  = 0;
        for (const auto& cand : candidates_) {
            if (cand.reviewed) {
                ++c.candidatesReviewed;
                if (cand.verdict == "confirmed") ++c.confirmedDefects;
                else if (cand.verdict == "false_positive") ++c.falsePositives;
                else if (cand.verdict == "needs_runtime_proof") ++c.needsRuntimeProof;
            }
        }
        c.candidatesPending = c.candidatesTotal - c.candidatesReviewed;
        c.filesReviewed     = reviewedFiles_.size();
        return c;
    }

    const std::vector<AuditCandidate>& candidates() const { return candidates_; }
    const std::vector<std::string>& enumeratedFiles() const { return enumerated_; }

    // Deterministic completion authority — the runtime decides, never the model.
    // The scanner IS the exhaustive file-level review stage: filesScanned ==
    // filesEnumerated proves 100% codebase coverage without pretending the
    // LLM personally read every file. The model reviews CANDIDATES, not all
    // files.
    bool coverageComplete() const {
        const AuditCounters c = counters();
        return c.filesEnumerated > 0 &&
               c.filesEnumerated == c.filesTotal &&
               c.sourceScanComplete &&
               c.filesScanned == c.filesEnumerated &&
               c.candidatesPending == 0 &&
               c.toolFailures == 0;
    }

    // Durable snapshot for evidence receipts.
    bool writeSnapshot(const std::filesystem::path& jsonlOut) const;

    const std::filesystem::path& workspaceRoot() const { return root_; }

private:
    void persistLocked();          // appends one JSONL state line
    void persistCandidatesLocked();

    mutable std::mutex      mu_;
    std::filesystem::path   root_;
    std::filesystem::path   statePath_;
    std::vector<std::string> enumerated_;
    std::unordered_set<std::string> reviewedFiles_;
    std::vector<AuditCandidate> candidates_;
    AuditCounters           counters_;
    uint64_t                nextCandidateId_ = 1;
};

} // namespace agent
} // namespace rawrxd