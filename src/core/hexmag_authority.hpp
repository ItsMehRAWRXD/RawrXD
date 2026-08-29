// ============================================================================
// hexmag_authority.hpp — HexMag policy-resolution stack (chain of command)
// ============================================================================
// L0 CORE > L1 CONSTITUTION > L2 MISSION > L3 ROLE > L4 TOOL >
// L5 CONTEXT > L6 STRATEGY > L7 GENERATED ACTION
//
// Authority, Evidence, and Confidence are INDEPENDENT.
// agent_confidence must NEVER imply claim_verified.
// ============================================================================
#ifndef RAWRXD_HEXMAG_AUTHORITY_HPP
#define RAWRXD_HEXMAG_AUTHORITY_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace RawrXD {
namespace HexMag {

/// Higher numeric value = higher authority (wins conflicts).
enum class Authority : uint8_t {
    GeneratedAction = 0,  // L7
    AgentStrategy   = 1,  // L6
    Context         = 2,  // L5
    ToolContract    = 3,  // L4
    AgentRole       = 4,  // L3
    Mission         = 5,  // L2
    Constitution    = 6,  // L1
    CoreInvariant   = 7,  // L0
};

enum class HexMagRole : uint8_t {
    Scout = 0,
    Prover,
    Patcher,
    Reverse,
    RedTeam,
    Arbiter,
    Recorder,
    Generalist,
};

enum class FailureClass : uint8_t {
    None = 0,
    Contradiction,
    Counterexample,
    UnsupportedClaim,
    TestFailure,
    Stagnation,
    MissingInformation,
    Wrong,
    NoInformationGain,
};

enum class ClaimState : uint8_t {
    Candidate = 0,
    UnderReview,
    Contradicted,
    MissingInput,
    Verified,
    Proven,
    FinalRejected,
};

/// L0 — impossible for an agent to override.
struct CoreInvariant {
    bool forbidUnsupportedClaims = true;
    bool forbidFabricatedEvidence = true;
    bool requireToolContractCompliance = true;
    bool requireAuthorityOrdering = true;
    bool forbidConfidenceAsEvidence = true;
    bool forbidGuessingMissingFacts = true;
};

inline constexpr CoreInvariant kCoreInvariants{};

struct Directive {
    uint64_t id = 0;
    Authority authority = Authority::GeneratedAction;
    std::string source;
    std::string instruction;
    bool immutable = false;
    bool verified = false;
    uint64_t parentDirective = 0;
};

struct Evidence {
    std::string kind;       // tensor_dump | harness | compile | reverse | user
    std::string payload;
    std::string tool;       // which tool contract produced it
    bool passesVerifier = false;
};

struct Claim {
    std::string text;
    ClaimState state = ClaimState::Candidate;
    double confidence = 0.0;   // NEVER used as verification
    std::vector<Evidence> evidence;
    uint64_t directiveId = 0;
    uint64_t generationId = 0;

    bool verified() const {
        for (const auto& e : evidence) {
            if (e.passesVerifier) return true;
        }
        return false;
    }
};

struct Attempt {
    uint64_t problemStateHash = 0;
    uint64_t strategyHash = 0;
    uint64_t evidenceHash = 0;
    FailureClass failure = FailureClass::None;
    double informationGain = 0.0;
    double confidenceDelta = 0.0;
    HexMagRole role = HexMagRole::Generalist;
    uint32_t strategyId = 0;
};

struct ToolContract {
    std::string name;
    std::vector<std::string> can;
    std::vector<std::string> cannot;
    std::string authorityDomain; // e.g. "numerical_parity"
    int rank = 0;                // higher preferred within domain
};

struct CommandEnvelope {
    Authority authority = Authority::Mission;
    HexMagRole role = HexMagRole::Generalist;
    std::string objective;
    std::vector<std::string> known;
    std::vector<std::string> forbidden;
    std::string evidenceRequired;
    std::string onMissingInformation = "ask_user";
    std::string onComputationalUncertainty = "grow_and_reverse";
    std::string onFailure = "submit_to_repeat_tuner";
};

enum class ResolveKind : uint8_t { Combine, AcceptA, AcceptB, EscalateArbiter };

struct ResolveResult {
    ResolveKind kind = ResolveKind::Combine;
    const Directive* chosen = nullptr;
    std::string reason;
};

inline bool conflicts(const Directive& a, const Directive& b) {
    if (a.instruction.empty() || b.instruction.empty()) return false;
    // Conservative: same topic markers with opposing forbid/allow
    const bool aForbid = a.instruction.find("FORBIDDEN") != std::string::npos
                      || a.instruction.find("DO NOT") != std::string::npos
                      || a.instruction.find("do not") != std::string::npos;
    const bool bForbid = b.instruction.find("FORBIDDEN") != std::string::npos
                      || b.instruction.find("DO NOT") != std::string::npos
                      || b.instruction.find("do not") != std::string::npos;
    if (aForbid != bForbid && a.instruction.size() > 8 && b.instruction.size() > 8) {
        // Overlapping keywords → treat as potential conflict
        return true;
    }
    return false;
}

inline ResolveResult resolve(const Directive& a, const Directive& b) {
    ResolveResult r;
    if (!conflicts(a, b)) {
        r.kind = ResolveKind::Combine;
        r.reason = "no_conflict";
        return r;
    }
    if (static_cast<uint8_t>(a.authority) > static_cast<uint8_t>(b.authority)) {
        r.kind = ResolveKind::AcceptA;
        r.chosen = &a;
        r.reason = "higher_authority_a";
        return r;
    }
    if (static_cast<uint8_t>(b.authority) > static_cast<uint8_t>(a.authority)) {
        r.kind = ResolveKind::AcceptB;
        r.chosen = &b;
        r.reason = "higher_authority_b";
        return r;
    }
    r.kind = ResolveKind::EscalateArbiter;
    r.reason = "equal_authority_conflict";
    return r;
}

/// Reject strategy repeat with no new evidence (constitution §6–7).
inline bool rejectRepeatWithoutGain(const Attempt& prev, const Attempt& next) {
    if (prev.failure == FailureClass::None) return false;
    if (next.problemStateHash != prev.problemStateHash) return false;
    if (next.strategyHash != prev.strategyHash) return false;
    if (next.evidenceHash != prev.evidenceHash) return false;
    if (next.informationGain > 1e-9) return false;
    return true;
}

/// FINAL gate: confidence is irrelevant; evidence required.
inline bool allowFinal(const Claim& c, const CoreInvariant& inv = kCoreInvariants) {
    if (inv.forbidUnsupportedClaims && !c.verified()) return false;
    if (inv.forbidConfidenceAsEvidence && c.confidence > 0.0 && !c.verified()) {
        // confidence alone never passes
        return false;
    }
    if (c.state == ClaimState::MissingInput || c.state == ClaimState::Contradicted
        || c.state == ClaimState::FinalRejected) {
        return false;
    }
    return c.state == ClaimState::Verified || c.state == ClaimState::Proven || c.verified();
}

inline const char* authorityName(Authority a) {
    switch (a) {
        case Authority::GeneratedAction: return "GENERATED_ACTION";
        case Authority::AgentStrategy:   return "AGENT_STRATEGY";
        case Authority::Context:         return "CONTEXT";
        case Authority::ToolContract:    return "TOOL_CONTRACT";
        case Authority::AgentRole:       return "AGENT_ROLE";
        case Authority::Mission:         return "MISSION";
        case Authority::Constitution:    return "CONSTITUTION";
        case Authority::CoreInvariant:   return "CORE_INVARIANT";
    }
    return "?";
}

inline const char* roleName(HexMagRole r) {
    switch (r) {
        case HexMagRole::Scout:      return "SCOUT";
        case HexMagRole::Prover:     return "PROVER";
        case HexMagRole::Patcher:    return "PATCHER";
        case HexMagRole::Reverse:    return "REVERSE";
        case HexMagRole::RedTeam:    return "REDTEAM";
        case HexMagRole::Arbiter:    return "ARBITER";
        case HexMagRole::Recorder:   return "RECORDER";
        case HexMagRole::Generalist: return "GENERALIST";
    }
    return "?";
}

} // namespace HexMag
} // namespace RawrXD

#endif
