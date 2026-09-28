#pragma once
// ============================================================================
// EvidenceStatus.hpp — RAWRXD_EVIDENCE_STATUS_001
//
// First-class execution-status stream, independent from Thinking.
// Evaluates whether model claims (e.g., TASK_COMPLETE) are actually
// supported by runtime/build/certification evidence.
//
// Placement: immediately after model output, before completion/promotion dispatch.
//   AgentResult result = model.run(...);
//   EvidenceStatus evidence = evidenceAuthority.evaluate(result, runtimeLedger, ...);
//   ui.publishEvidence(evidence);
//   if (result.requestsTaskComplete() && !evidence.taskCompleteAllowed) { ... }
// ============================================================================

#include "Common.hpp"
#include <string>
#include <vector>

namespace rawrxd::closure {

// ---------------------------------------------------------------------------
// EvidenceState — whether a claim is actually supported
// ---------------------------------------------------------------------------
enum class EvidenceState : uint8_t {
    Unknown     = 0,
    Supported   = 1,
    Partial     = 2,
    Premature   = 3,
    Unsupported = 4,
    Incomplete  = 5,
    Contradicted = 6,
    Verified    = 7,
    AuthorityViolation = 8,
    CapabilityAbsent = 9
};

inline const char* to_string(EvidenceState s) noexcept {
    switch (s) {
        case EvidenceState::Unknown:      return "UNKNOWN";
        case EvidenceState::Supported:    return "SUPPORTED";
        case EvidenceState::Partial:      return "PARTIAL";
        case EvidenceState::Premature:    return "PREMATURE";
        case EvidenceState::Unsupported:  return "UNSUPPORTED";
        case EvidenceState::Incomplete:   return "INCOMPLETE";
        case EvidenceState::Contradicted: return "CONTRADICTED";
        case EvidenceState::Verified:     return "VERIFIED";
        case EvidenceState::AuthorityViolation: return "AUTHORITY_VIOLATION";
        case EvidenceState::CapabilityAbsent: return "CAPABILITY_ABSENT";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// EvidenceOrigin — where an observation came from
// ---------------------------------------------------------------------------
enum class EvidenceOrigin : uint8_t {
    Authority     = 0,
    Build         = 1,
    Runtime       = 2,
    Certification = 3,
    User          = 4
};

// ---------------------------------------------------------------------------
// EvidenceScope — granularity of an observation
// ---------------------------------------------------------------------------
enum class EvidenceScope : uint8_t {
    Task    = 0,
    Function = 1,
    Module  = 2,
    Pipeline = 3,
    System  = 4
};

// ---------------------------------------------------------------------------
// EvidenceValue — polymorphic observation value
// ---------------------------------------------------------------------------
struct EvidenceValue {
    enum class Type : uint8_t { Bool, Int64, Double, String } type = Type::Bool;
    union {
        bool     b;
        int64_t  i;
        double   d;
    };
    std::string s; // only valid when type == String

    EvidenceValue() noexcept : b(false) {}
    explicit EvidenceValue(bool v)       noexcept : type(Type::Bool),  b(v) {}
    explicit EvidenceValue(int64_t v)    noexcept : type(Type::Int64), i(v) {}
    explicit EvidenceValue(double v)     noexcept : type(Type::Double),d(v) {}
    explicit EvidenceValue(std::string v)noexcept : type(Type::String),s(std::move(v)) {}

    bool operator==(const EvidenceValue& o) const noexcept {
        if (type != o.type) return false;
        switch (type) {
            case Type::Bool:   return b == o.b;
            case Type::Int64:  return i == o.i;
            case Type::Double: return d == o.d;
            case Type::String: return s == o.s;
        }
        return false;
    }
    bool operator!=(const EvidenceValue& o) const noexcept { return !(*this == o); }
};

// ---------------------------------------------------------------------------
// EvidenceObservation — a single runtime or build witness
// ---------------------------------------------------------------------------
struct EvidenceObservation {
    EvidenceOrigin origin      = EvidenceOrigin::Runtime;
    EvidenceScope  scope       = EvidenceScope::Task;
    std::string    key;        // e.g., "HOST_FORWARD_LAYER_CALLS"
    EvidenceValue  value;
    std::string    timestamp;  // ISO-8601
    std::string    sourceFile;
    uint32_t       sourceLine  = 0;
    uint32_t       layerIndex  = UINT32_MAX;
    std::string    tensorName;
    std::string    operation;   // e.g., "QuantGemv"
};

// ---------------------------------------------------------------------------
// reconcile — compare observations for contradiction
// ---------------------------------------------------------------------------
EvidenceState reconcile(const std::vector<EvidenceObservation>& observations);
// GateLedger — tracks which mandatory evidence gates have passed
// ---------------------------------------------------------------------------
struct GateLedger {
    bool taskCompleteClaimed = false;

    // Authority audit gates
    bool authorityAuditValid = false;
    bool sourceAuthorityVerified = false;
    bool recursiveSymbolAuditValid = false;
    bool semanticBehaviorMapped = false;

    // Build gates
    bool configureRan = false;
    bool compileRan = false;
    bool linkRan = false;

    // Runtime gates
    bool runtimeRan = false;
    bool processCreated = false;
    bool processSurvivedStartup = false;
    bool ideLaunch = false;

    // Inference gates
    bool modelLoaded = false;
    bool tokenizerReady = false;
    bool prefillReached = false;
    bool decodeReached = false;
    bool forwardReached = false;
    bool logitsFinite = false;

    // Certification gates
    bool beaconismRuntimeEvaluated = false;
    bool shippingExecutableCertified = false;
    bool promoteAllowed = false;

    // Mirror/defect tracking
    bool mirrorTerminologyAbsent = false;
    bool equivalentBehaviorMapped = false;

    // GPU capability tracking
    bool gpuCapabilityAbsent = false;
    std::string gpuCapabilityReason;

    std::vector<std::string> satisfiedGates;
    std::vector<std::string> unsatisfiedGates;

    void markSatisfied(const std::string& gate);
    void markUnsatisfied(const std::string& gate);

    bool allMandatoryPassed() const;
    bool hasClaimWithoutWitness() const;
    std::string firstUnsatisfied() const;
};

// ---------------------------------------------------------------------------
// EvidenceStatus — the evaluated result published to the UI stream
// ---------------------------------------------------------------------------
struct EvidenceStatus {
    EvidenceState state = EvidenceState::Unknown;
    bool premature = false;
    bool unsupported = false;
    bool promoteAllowed = false;
    bool taskCompleteAllowed = false;

    std::string claim;                    // e.g., "TASK_COMPLETE"
    std::string reason;                   // Human-readable explanation
    std::string firstUnsatisfiedGate;     // First gate still open

    // Capability absence (e.g., GPU forward path absent in authoritative source)
    bool capabilityAbsent = false;
    std::string capabilityReason;

    // Execution summary (for UI display)
    struct ExecutionSummary {
        bool buildRan = false;
        bool runtimeRan = false;
        bool inferenceRan = false;
        bool certificationRan = false;
    } execution;

    // Certification summary
    struct CertificationSummary {
        bool promote = false;
        bool taskComplete = false;
        std::string verdict = "INCOMPLETE";
    } certification;

    // RawrXD-specific classification fields
    struct RawrXDDisposition {
        bool shippingExecutableCertified = false;
        bool beaconismTransferRequired = false;
        std::string beaconismReason;
        int promote = 0;
        std::string verdict = "INCOMPLETE";
    } rawrxd;
};

// ---------------------------------------------------------------------------
// EvidenceAuthority — classifies model claims against actual evidence
// ---------------------------------------------------------------------------
class EvidenceAuthority {
public:
    // Primary evaluation: classify a claimed completion against gate evidence
    EvidenceStatus evaluate(
        bool taskCompleteClaimed,
        const GateLedger& ledger);

    // Convenience: evaluate with default claim = "TASK_COMPLETE"
    EvidenceStatus evaluate(const GateLedger& ledger);

    // Streaming JSON representation for UI channel
    static std::string toJson(const EvidenceStatus& status);

    // Compact label for collapsed UI display
    static std::string toLabel(const EvidenceStatus& status);

private:
    EvidenceStatus classifyPremature(const GateLedger& ledger);
    EvidenceStatus classifyUnsupported(const GateLedger& ledger);
    EvidenceStatus classifyVerified(const GateLedger& ledger);
    EvidenceStatus classifyIncomplete(const GateLedger& ledger);
    EvidenceStatus classifyCapabilityAbsent(const GateLedger& ledger);
};

// ---------------------------------------------------------------------------
// RawrXD-specific gate classifier (as specified in RAWRXD_BEACONISM_AUTHORITY_001)
// ---------------------------------------------------------------------------
EvidenceStatus classifyRawrXD(const GateLedger& ledger);

} // namespace rawrxd::closure
