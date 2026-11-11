#pragma once
// Deep2 GPU-forward diagnostic chain control plane.
// CONTROL ONLY: never owns runtime evidence and never promotes a claim.

#include <cstdint>
#include <string>
#include <vector>

namespace deep2::control {

enum class ChainDisposition : uint32_t {
    Pending = 0,
    PassRuntime,
    BlockedSafeBypass,
    BlockedEvidence,
    BlockedProvenance,
    BlockedExecution,
    CompleteNoWinner,
    CompleteWinnerObserved
};

struct GateSpec {
    const char* id;
    const char* child;
    bool untouched;
};

struct GateReceipt {
    std::string gate;
    std::string child;
    std::string modelFingerprint;
    std::string blockedAt;
    std::string claimAuthority;
    int exitCode = -1;
    bool runtimeAuthority = false;
    bool modelProvenanceMatch = false;
    bool promote = false;
    bool ollamaHttp = true;
    bool ignoreRequested = false;
    bool ignoreApplied = false;
    uint64_t tokensCommitted = 0;
    double gpuForwardMs = -1.0;
    double childMs = -1.0;
    uint64_t childCalls = 0;
    ChainDisposition disposition = ChainDisposition::Pending;
};

struct Attribution {
    std::string gate;
    std::string child;
    double baselineGpuForwardMs = 0.0;
    double candidateGpuForwardMs = 0.0;
    double deltaGpuForwardMs = 0.0;
    double attributionRatio = 0.0;
    bool ownTimingAgrees = false;
    bool observedCandidate = false;
};

struct ChainPolicy {
    uint64_t requiredTokens = 20;
    double materialCollapseRatio = 0.20; // diagnostic threshold, not promotion.
    double ownTimingAgreementTolerance = 0.35;
    bool requireSameFingerprint = true;
    bool requireOwnRuntimeEmission = true;
    bool requireOllamaHttpOff = true;
    bool requirePromoteOff = true;
};

const std::vector<GateSpec>& CanonicalGpuForwardGates();

bool ParseGateReceipt(const std::string& text, GateReceipt& out, std::string& why);
bool ValidateGateReceipt(const GateReceipt& r,
                         const ChainPolicy& policy,
                         const std::string& baselineFingerprint,
                         std::string& why);
Attribution CompareAgainstBaseline(const GateReceipt& g0,
                                   const GateReceipt& candidate,
                                   const ChainPolicy& policy);
const char* ToString(ChainDisposition d);

} // namespace deep2::control
