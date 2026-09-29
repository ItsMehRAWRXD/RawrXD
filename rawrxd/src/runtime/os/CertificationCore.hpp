// ============================================================================
// CertificationCore.hpp — Independent evaluation of frozen subjects
// Pipeline: Import → Freeze → Oracle → Truth → Consensus → Verdict → Receipt
// SEPARATE from GenerationCore (generation proposes, certification decides)
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <unordered_map>

namespace rawrxd::certification {

// ---------------------------------------------------------------------------
// Subject — a frozen generation candidate for certification
// ---------------------------------------------------------------------------
struct Subject {
    std::string id;
    std::string content;            // the frozen candidate content
    std::string fingerprint;        // hash of content (immutable after freeze)
    std::string sourceReceiptId;    // generation receipt that produced this
    bool frozen = false;
};

// ---------------------------------------------------------------------------
// Evidence — collected proof about the subject
// ---------------------------------------------------------------------------
struct Evidence {
    std::string type;               // "structural", "numerical", "determinism"
    std::string description;
    bool pass = false;
    std::string detail;
};

// ---------------------------------------------------------------------------
// TruthResult — comparison against an independent oracle
// ---------------------------------------------------------------------------
struct TruthResult {
    bool structuralMatch = false;
    bool numericalMatch = false;
    bool determinismMatch = false;
    std::string oracleId;
    std::string difference;
};

// ---------------------------------------------------------------------------
// Verdict — the final certification decision
// ---------------------------------------------------------------------------
enum class VerdictType : uint8_t {
    Pass = 0,
    Fail = 1,
    Hold = 2,
    Inconclusive = 3,
};

struct Verdict {
    VerdictType type = VerdictType::Inconclusive;
    std::string reason;
    std::vector<Evidence> evidence;
    TruthResult truth;
};

// ---------------------------------------------------------------------------
// Certification Receipt — the sealed output (separate from generation receipt)
// ---------------------------------------------------------------------------
struct CertificationReceipt {
    std::string receiptId;
    std::string subjectId;
    std::string subjectFingerprint;
    VerdictType verdict = VerdictType::Inconclusive;
    std::string verdictReason;
    std::vector<Evidence> evidence;
    TruthResult truth;
    std::string timestamp;
    bool sealed = false;

    // Provenance — this is SEPARATE from generation
    std::string generationReceiptId;  // link back (but no authority over generation)
    std::string oracleId;
};

// ---------------------------------------------------------------------------
// CertificationCore — the handwritten certification pipeline
// FAIL-CLOSED: if any check is uncertain, verdict = Hold or Fail
// DOES NOT generate — only evaluates what GenerationCore already produced
// ---------------------------------------------------------------------------
class CertificationCore {
public:
    // Phase 1: Import subject from generation
    Subject importSubject(const std::string& content,
                          const std::string& generationReceiptId);

    // Phase 2: Freeze subject (compute fingerprint, make immutable)
    bool freezeSubject(Subject& subject);

    // Phase 3: Run oracle comparison
    TruthResult runOracle(const Subject& subject,
                          const std::string& oracleExpectedContent);

    // Phase 4: Collect evidence
    std::vector<Evidence> collectEvidence(const Subject& subject,
                                           const TruthResult& truth);

    // Phase 5: Issue verdict
    Verdict issueVerdict(const TruthResult& truth,
                         const std::vector<Evidence>& evidence);

    // Phase 6: Seal certification receipt
    CertificationReceipt sealReceipt(const Subject& subject,
                                     const Verdict& verdict,
                                     const std::string& generationReceiptId);

    // Full pipeline (convenience)
    CertificationReceipt certify(const std::string& content,
                                 const std::string& generationReceiptId,
                                 const std::string& oracleExpectedContent);

    // Metrics
    int totalCertifications() const { return totalCert_.load(); }
    int passCount() const { return passCount_.load(); }
    int failCount() const { return failCount_.load(); }
    int holdCount() const { return holdCount_.load(); }

private:
    std::atomic<int> totalCert_{0};
    std::atomic<int> passCount_{0};
    std::atomic<int> failCount_{0};
    std::atomic<int> holdCount_{0};
    std::atomic<int> receiptCounter_{0};

    std::string makeId(const std::string& prefix);
    std::string computeFingerprint(const std::string& content);
};

} // namespace rawrxd::certification