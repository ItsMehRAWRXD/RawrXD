#include "GpuForwardChain.hpp"
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <sstream>
#include <unordered_map>

namespace deep2::control {

static const std::vector<GateSpec> kGates = {
    {"G0_REFERENCE",          "NONE",              true },
    {"G1_GPU_QKV",            "QKV",               false},
    {"G2_DEVICE_ATTENTION",   "DEVICE_ATTENTION",  false},
    {"G3_FFN",                "FFN",               false},
    {"G4_GEMV",               "GEMV",              false},
    {"G5_OUTPUT_PROJECTION",  "OUTPUT_PROJECTION", false},
    {"G6_KV",                 "KV",                false},
    {"G7_SYNC",               "SYNC",              false},
    {"G8_READBACK",           "READBACK",          false},
};

const std::vector<GateSpec>& CanonicalGpuForwardGates() { return kGates; }

static std::string trim(std::string s) {
    const auto a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    const auto b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b-a+1);
}
static bool bval(const std::string& s) {
    return s=="1" || s=="YES" || s=="TRUE" || s=="PASS";
}
static uint64_t u64(const std::string& s) {
    char* e=nullptr;
    const auto v = std::strtoull(s.c_str(), &e, 10);
    return (e && *e==0) ? static_cast<uint64_t>(v) : 0;
}
static double f64(const std::string& s) {
    char* e=nullptr;
    const auto v = std::strtod(s.c_str(), &e);
    return (e && *e==0) ? v : -1.0;
}

bool ParseGateReceipt(const std::string& text, GateReceipt& out, std::string& why) {
    std::unordered_map<std::string,std::string> kv;
    std::istringstream is(text);
    std::string line;
    while (std::getline(is,line)) {
        const auto p=line.find('=');
        if (p==std::string::npos) continue;
        auto k=trim(line.substr(0,p));
        auto v=trim(line.substr(p+1));
        if (!k.empty()) kv[k]=v;
    }

    auto get=[&](const char* k)->std::string {
        auto it=kv.find(k); return it==kv.end()?std::string():it->second;
    };

    out.gate=get("GATE");
    out.child=get("GPU_FORWARD_CHILD_IGNORE");
    if (out.child.empty()) out.child=get("CHILD");
    out.modelFingerprint=get("MODEL_FP");
    if (out.modelFingerprint.empty()) out.modelFingerprint=get("MODEL_FINGERPRINT");
    out.blockedAt=get("BLOCKED_AT");
    out.claimAuthority=get("CLAIM_AUTHORITY");
    out.runtimeAuthority=bval(get("RUNTIME_AUTHORITY"));
    out.modelProvenanceMatch=bval(get("MODEL_PROVENANCE_MATCH"));
    out.promote=bval(get("PROMOTE"));
    out.ollamaHttp=!(!get("OLLAMA_HTTP").empty() && get("OLLAMA_HTTP")=="0");
    out.ignoreRequested=bval(get("IGNORE_REQUESTED"));
    if (!out.ignoreRequested) out.ignoreRequested=bval(get("GPU_FORWARD_CHILD_IGNORE_REQUESTED"));
    out.ignoreApplied=bval(get("IGNORE_APPLIED"));
    if (!out.ignoreApplied) out.ignoreApplied=bval(get("GPU_FORWARD_CHILD_IGNORE_APPLIED"));
    out.tokensCommitted=u64(get("TOKENS_COMMITTED"));
    out.gpuForwardMs=f64(get("GPU_FORWARD_MS"));
    out.childMs=f64(get("CHILD_MS"));
    out.childCalls=u64(get("CHILD_CALLS"));

    // Accept child-specific emitted names too, e.g. QKV_MS/QKV_CALLS/QKV_IGNORE_APPLIED.
    if (!out.child.empty() && out.child!="NONE") {
        if (out.childMs < 0) out.childMs=f64(get((out.child+"_MS").c_str()));
        if (out.childCalls == 0) out.childCalls=u64(get((out.child+"_CALLS").c_str()));
        if (!out.ignoreRequested) out.ignoreRequested=bval(get((out.child+"_IGNORE_REQUESTED").c_str()));
        if (!out.ignoreApplied) out.ignoreApplied=bval(get((out.child+"_IGNORE_APPLIED").c_str()));
    }

    if (out.gate.empty()) { why="missing GATE"; return false; }
    if (out.claimAuthority.empty()) { why="missing CLAIM_AUTHORITY"; return false; }
    if (out.gpuForwardMs < 0) { why="missing/invalid GPU_FORWARD_MS"; return false; }
    why.clear();
    return true;
}

bool ValidateGateReceipt(const GateReceipt& r,
                         const ChainPolicy& p,
                         const std::string& baselineFp,
                         std::string& why) {
    if (p.requireOwnRuntimeEmission &&
        r.claimAuthority != "OWN_RUNTIME_EMISSION_ONLY") {
        why="CLAIM_AUTHORITY is not OWN_RUNTIME_EMISSION_ONLY";
        return false;
    }
    if (!r.runtimeAuthority) { why="RUNTIME_AUTHORITY != 1"; return false; }
    if (!r.modelProvenanceMatch) { why="MODEL_PROVENANCE_MATCH != 1"; return false; }
    if (p.requireSameFingerprint && !baselineFp.empty() &&
        r.modelFingerprint != baselineFp) {
        why="model fingerprint differs from G0";
        return false;
    }
    if (p.requirePromoteOff && r.promote) { why="PROMOTE != 0"; return false; }
    if (p.requireOllamaHttpOff && r.ollamaHttp) { why="OLLAMA_HTTP != 0"; return false; }
    if (r.tokensCommitted != p.requiredTokens) {
        why="TOKENS_COMMITTED != required token count";
        return false;
    }
    if (!r.blockedAt.empty() && r.blockedAt!="NONE" &&
        r.blockedAt!="SAFE_BYPASS") {
        why="runtime blocked at "+r.blockedAt;
        return false;
    }
    why.clear();
    return true;
}

Attribution CompareAgainstBaseline(const GateReceipt& g0,
                                   const GateReceipt& c,
                                   const ChainPolicy& p) {
    Attribution a;
    a.gate=c.gate; a.child=c.child;
    a.baselineGpuForwardMs=g0.gpuForwardMs;
    a.candidateGpuForwardMs=c.gpuForwardMs;
    if (g0.gpuForwardMs <= 0.0) return a;

    a.deltaGpuForwardMs=g0.gpuForwardMs-c.gpuForwardMs;
    a.attributionRatio=a.deltaGpuForwardMs/g0.gpuForwardMs;

    // Runtime child timing is corroboration. It does not create ownership by itself.
    if (c.childMs >= 0.0 && a.deltaGpuForwardMs > 0.0) {
        const double denom=std::max(c.childMs, a.deltaGpuForwardMs);
        const double err=std::fabs(c.childMs-a.deltaGpuForwardMs)/denom;
        a.ownTimingAgrees = err <= p.ownTimingAgreementTolerance;
    }
    a.observedCandidate =
        c.ignoreApplied &&
        c.childCalls > 0 &&
        a.attributionRatio >= p.materialCollapseRatio &&
        a.ownTimingAgrees;
    return a;
}

const char* ToString(ChainDisposition d) {
    switch(d) {
      case ChainDisposition::Pending: return "PENDING";
      case ChainDisposition::PassRuntime: return "PASS_RUNTIME";
      case ChainDisposition::BlockedSafeBypass: return "BLOCKED_SAFE_BYPASS";
      case ChainDisposition::BlockedEvidence: return "BLOCKED_EVIDENCE";
      case ChainDisposition::BlockedProvenance: return "BLOCKED_PROVENANCE";
      case ChainDisposition::BlockedExecution: return "BLOCKED_EXECUTION";
      case ChainDisposition::CompleteNoWinner: return "COMPLETE_NO_WINNER";
      case ChainDisposition::CompleteWinnerObserved: return "COMPLETE_WINNER_OBSERVED";
    }
    return "UNKNOWN";
}

} // namespace deep2::control
