// ============================================================================
// hexmag_oracle_binder.hpp — Oracle/Deep2 → CANDIDATE_ONLY binder
// ============================================================================
// HEXMAG_ORACLE_BINDER_001
//
//   oracle_output         = CANDIDATE_ONLY
//   deep2_output          = CANDIDATE_ONLY
//   candidate_as_evidence = FORBIDDEN
//   candidate_as_final    = FORBIDDEN
//   verified candidate + allowFinal + isAllowedFinalClaim = ALLOW_FINAL
//
// needInput == true  ⇒  Oracle/Deep2 MUST NOT run; FINAL cannot be resurrected.
// ============================================================================
#ifndef RAWRXD_HEXMAG_ORACLE_BINDER_HPP
#define RAWRXD_HEXMAG_ORACLE_BINDER_HPP

#include "core/hexmag_authority.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace RawrXD {
namespace HexMag {

enum class CandidateStatus : uint8_t {
    Ok = 0,
    Empty,
    Malformed,
    UnsupportedClaim,
    OracleFailure,
    SkippedNeedInput,
};

enum class CandidateSource : uint8_t {
    None = 0,
    Oracle,   // advisory / solver surface (may be W0 or neural)
    Deep2,    // tensor path — optional; never FINAL authority
    Scripted, // cert stand-in
    W0,       // weightless Deep2-W0 symbolic solver (zero tensor weights)
};

struct CandidateArtifact {
    std::string text;
    CandidateSource source = CandidateSource::None;
    CandidateStatus status = CandidateStatus::Empty;
    bool hadFinalWording = false; // stripped; never authority
};

/// Pluggable inference surface (Deep2 / ReasoningOracle / scripted cert).
struct CandidateGenerator {
    virtual ~CandidateGenerator() = default;
    virtual bool available() const = 0;
    virtual CandidateSource source() const = 0;
    /// Raw model/oracle text. Empty string ⇒ OracleFailure (unless needInput skip).
    virtual std::string generate(const std::string& prompt,
                                 const std::string& roleContext) = 0;
};

/// Thin adapter — any callable (Deep2 generate, ReasoningOracle::ask, lambda).
struct FunctionCandidateGenerator final : CandidateGenerator {
    CandidateSource src = CandidateSource::Oracle;
    bool avail = true;
    std::function<std::string(const std::string&, const std::string&)> fn;

    bool available() const override { return avail && static_cast<bool>(fn); }
    CandidateSource source() const override { return src; }
    std::string generate(const std::string& prompt,
                         const std::string& roleContext) override {
        if (!fn) return {};
        return fn(prompt, roleContext);
    }
};

using CandidateVerifierFn = std::function<bool(const CandidateArtifact&)>;

struct BinderRequest {
    std::string prompt;
    std::string context;
    bool needInputLatched = false;
    uint32_t maxCandidates = 3;
};

struct BinderResult {
    bool oracleInvoked = false;
    bool deep2Invoked = false;
    bool codegenInvoked = false; // any generator ran
    std::vector<CandidateArtifact> candidates;
    CandidateArtifact selected;
    Claim claim; // Candidate unless verifier attaches evidence
    bool gateAllowFinal = false;
    bool gateIsAllowedFinalClaim = false;
    bool success = false; // FINAL allowed by existing gates
    std::string error;
    std::string detail;
    std::string selectionEvidence; // deterministic pick rationale
};

/// Case-insensitive deficit markers / missing actionable tokens (mirrors MASM).
bool goalLooksUnderspecified(const std::string& goal);

/// Strip FINAL-authority wording; classify empty/malformed/unsupported.
CandidateArtifact sanitizeCandidate(std::string raw, CandidateSource src);

/// Deterministic pick among Ok candidates (FNV of text; lowest wins).
CandidateArtifact selectDeterministic(const std::vector<CandidateArtifact>& cands,
                                      std::string* evidenceOut);

/// Full binder pipeline. Does not emit FINAL itself — only builds a Claim
/// for the existing allowFinal + isAllowedFinalClaim gates.
BinderResult runOracleBinder(const BinderRequest& req,
                             const std::vector<CandidateGenerator*>& generators,
                             CandidateVerifierFn verifier);

/// Process-wide optional generators for askWithAutoStart enrichment.
void setOracleBinderGenerators(std::vector<CandidateGenerator*> generators);
std::vector<CandidateGenerator*> oracleBinderGenerators();
void setOracleBinderVerifier(CandidateVerifierFn verifier);
CandidateVerifierFn oracleBinderVerifier();
void clearOracleBinderHooks();

inline const char* candidateStatusName(CandidateStatus s) {
    switch (s) {
        case CandidateStatus::Ok: return "ok";
        case CandidateStatus::Empty: return "empty";
        case CandidateStatus::Malformed: return "malformed";
        case CandidateStatus::UnsupportedClaim: return "unsupported_claim";
        case CandidateStatus::OracleFailure: return "oracle_failure";
        case CandidateStatus::SkippedNeedInput: return "skipped_need_input";
    }
    return "?";
}

inline const char* candidateSourceName(CandidateSource s) {
    switch (s) {
        case CandidateSource::None: return "none";
        case CandidateSource::Oracle: return "oracle";
        case CandidateSource::Deep2: return "deep2";
        case CandidateSource::Scripted: return "scripted";
        case CandidateSource::W0: return "w0";
    }
    return "?";
}

} // namespace HexMag
} // namespace RawrXD

#endif
