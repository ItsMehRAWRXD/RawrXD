// ============================================================================
// EvidenceStatus.cpp — RAWRXD_EVIDENCE_STATUS_001 Implementation
// ============================================================================

#include "rawrxd/closure/EvidenceStatus.hpp"
#include <sstream>
#include <iomanip>

namespace rawrxd::closure {

namespace {
    std::string json_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: out += c; break;
            }
        }
        return out;
    }

    const char* to_string(EvidenceOrigin o) noexcept {
        switch (o) {
            case EvidenceOrigin::Authority:     return "Authority";
            case EvidenceOrigin::Build:         return "Build";
            case EvidenceOrigin::Runtime:       return "Runtime";
            case EvidenceOrigin::Certification: return "Certification";
            case EvidenceOrigin::User:          return "User";
        }
        return "Unknown";
    }

    const char* to_string(EvidenceScope s) noexcept {
        switch (s) {
            case EvidenceScope::Task:    return "Task";
            case EvidenceScope::Function:return "Function";
            case EvidenceScope::Module:  return "Module";
            case EvidenceScope::Pipeline:return "Pipeline";
            case EvidenceScope::System:  return "System";
        }
        return "Unknown";
    }

    void value_to_json(std::ostringstream& oss, const EvidenceValue& v) {
        switch (v.type) {
            case EvidenceValue::Type::Bool:   oss << (v.b ? "true" : "false"); break;
            case EvidenceValue::Type::Int64:  oss << v.i; break;
            case EvidenceValue::Type::Double: oss << std::fixed << std::setprecision(6) << v.d; break;
            case EvidenceValue::Type::String: oss << "\"" << json_escape(v.s) << "\""; break;
        }
    }
}

// ---------------------------------------------------------------------------
// reconcile — compare observations for contradiction
// ---------------------------------------------------------------------------
EvidenceState reconcile(const std::vector<EvidenceObservation>& observations) {
    if (observations.empty())
        return EvidenceState::Unknown;

    const EvidenceValue& first = observations.front().value;
    for (const auto& o : observations) {
        if (o.value != first)
            return EvidenceState::Contradicted;
    }
    return EvidenceState::Verified;
}

// ---------------------------------------------------------------------------
// GateLedger
// ---------------------------------------------------------------------------
void GateLedger::markSatisfied(const std::string& gate) {
    satisfiedGates.push_back(gate);
    auto it = std::find(unsatisfiedGates.begin(), unsatisfiedGates.end(), gate);
    if (it != unsatisfiedGates.end()) {
        unsatisfiedGates.erase(it);
    }
}

void GateLedger::markUnsatisfied(const std::string& gate) {
    if (std::find(unsatisfiedGates.begin(), unsatisfiedGates.end(), gate) == unsatisfiedGates.end()) {
        unsatisfiedGates.push_back(gate);
    }
}

bool GateLedger::allMandatoryPassed() const {
    return authorityAuditValid &&
           sourceAuthorityVerified &&
           configureRan &&
           compileRan &&
           linkRan &&
           runtimeRan &&
           processCreated &&
           processSurvivedStartup &&
           modelLoaded &&
           tokenizerReady &&
           prefillReached &&
           decodeReached &&
           forwardReached &&
           logitsFinite &&
           shippingExecutableCertified;
}

bool GateLedger::hasClaimWithoutWitness() const {
    return taskCompleteClaimed && !allMandatoryPassed();
}

std::string GateLedger::firstUnsatisfied() const {
    if (!unsatisfiedGates.empty()) {
        return unsatisfiedGates.front();
    }
    // Check mandatory gates in order
    if (!authorityAuditValid)       return "CORRECT_RECURSIVE_AUTHORITATIVE_SOURCE_AUDIT";
    if (!sourceAuthorityVerified)   return "SOURCE_AUTHORITY";
    if (!configureRan)              return "AUTHORITATIVE_BUILD_CONFIGURE";
    if (!compileRan)              return "AUTHORITATIVE_BUILD_COMPILE";
    if (!linkRan)                 return "AUTHORITATIVE_BUILD_LINK";
    if (!runtimeRan)              return "SHIPPING_EXECUTABLE_LAUNCH";
    if (!processCreated)          return "PROCESS_CREATED";
    if (!processSurvivedStartup)  return "PROCESS_SURVIVED_STARTUP";
    if (!modelLoaded)             return "MODEL_LOAD";
    if (!tokenizerReady)          return "TOKENIZER_READY";
    if (!prefillReached)          return "PREFILL_REACHED";
    if (!decodeReached)           return "DECODE_REACHED";
    if (!forwardReached)          return "FORWARD_REACHED";
    if (!logitsFinite)            return "LOGITS_FINITE";
    if (!shippingExecutableCertified) return "SHIPPING_EXECUTABLE_CERTIFIED";
    return "NONE";
}

// ---------------------------------------------------------------------------
// EvidenceAuthority::evaluate
// ---------------------------------------------------------------------------
EvidenceStatus EvidenceAuthority::evaluate(bool taskCompleteClaimed,
                                             const GateLedger& ledger) {
    GateLedger mutableLedger = ledger;
    mutableLedger.taskCompleteClaimed = taskCompleteClaimed;

    if (taskCompleteClaimed &&
        (!ledger.authorityAuditValid ||
         !ledger.configureRan ||
         !ledger.compileRan ||
         !ledger.linkRan ||
         !ledger.runtimeRan)) {
        auto s = classifyPremature(ledger);
        s.claim = "TASK_COMPLETE";
        return s;
    }

    if (ledger.gpuCapabilityAbsent) {
        auto s = classifyCapabilityAbsent(ledger);
        s.claim = "TASK_COMPLETE";
        return s;
    }

    if (ledger.hasClaimWithoutWitness()) {
        auto s = classifyUnsupported(ledger);
        s.claim = "TASK_COMPLETE";
        return s;
    }

    if (ledger.allMandatoryPassed()) {
        auto s = classifyVerified(ledger);
        s.claim = "TASK_COMPLETE";
        return s;
    }

    auto s = classifyIncomplete(ledger);
    s.claim = "TASK_COMPLETE";
    return s;
}

EvidenceStatus EvidenceAuthority::evaluate(const GateLedger& ledger) {
    return evaluate(ledger.taskCompleteClaimed, ledger);
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------
EvidenceStatus EvidenceAuthority::classifyPremature(const GateLedger& ledger) {
    EvidenceStatus s{};
    s.state = EvidenceState::Premature;
    s.premature = true;
    s.unsupported = true;
    s.promoteAllowed = false;
    s.taskCompleteAllowed = false;
    s.reason = "Completion claimed before mandatory evidence gates passed";
    s.firstUnsatisfiedGate = ledger.firstUnsatisfied();
    s.execution.buildRan = ledger.configureRan && ledger.compileRan && ledger.linkRan;
    s.execution.runtimeRan = ledger.runtimeRan;
    s.execution.inferenceRan = ledger.modelLoaded && ledger.tokenizerReady;
    s.certification.promote = false;
    s.certification.taskComplete = false;
    s.certification.verdict = "INCOMPLETE";
    s.rawrxd.shippingExecutableCertified = false;
    s.rawrxd.promote = 0;
    s.rawrxd.verdict = "INCOMPLETE";
    return s;
}

EvidenceStatus EvidenceAuthority::classifyUnsupported(const GateLedger& ledger) {
    EvidenceStatus s{};
    s.state = EvidenceState::Unsupported;
    s.unsupported = true;
    s.promoteAllowed = false;
    s.taskCompleteAllowed = false;
    s.reason = "Claim present without matching witness evidence";
    s.firstUnsatisfiedGate = ledger.firstUnsatisfied();
    s.execution.buildRan = ledger.configureRan && ledger.compileRan && ledger.linkRan;
    s.execution.runtimeRan = ledger.runtimeRan;
    s.execution.inferenceRan = ledger.modelLoaded && ledger.tokenizerReady;
    s.certification.promote = false;
    s.certification.taskComplete = false;
    s.certification.verdict = "INCOMPLETE";
    s.rawrxd.shippingExecutableCertified = false;
    s.rawrxd.promote = 0;
    s.rawrxd.verdict = "INCOMPLETE";
    return s;
}

EvidenceStatus EvidenceAuthority::classifyVerified(const GateLedger& ledger) {
    EvidenceStatus s{};
    s.state = EvidenceState::Verified;
    s.promoteAllowed = true;
    s.taskCompleteAllowed = true;
    s.reason = "All mandatory evidence gates satisfied";
    s.firstUnsatisfiedGate = "NONE";
    s.execution.buildRan = true;
    s.execution.runtimeRan = true;
    s.execution.inferenceRan = true;
    s.execution.certificationRan = true;
    s.certification.promote = true;
    s.certification.taskComplete = true;
    s.certification.verdict = "PASS";
    s.rawrxd.shippingExecutableCertified = true;
    s.rawrxd.promote = 1;
    s.rawrxd.verdict = "PASS";
    return s;
}

EvidenceStatus EvidenceAuthority::classifyIncomplete(const GateLedger& ledger) {
    EvidenceStatus s{};
    s.state = EvidenceState::Incomplete;
    s.promoteAllowed = false;
    s.taskCompleteAllowed = false;
    s.reason = "Mandatory evidence gates remain incomplete";
    s.firstUnsatisfiedGate = ledger.firstUnsatisfied();
    s.execution.buildRan = ledger.configureRan && ledger.compileRan && ledger.linkRan;
    s.execution.runtimeRan = ledger.runtimeRan;
    s.execution.inferenceRan = ledger.modelLoaded && ledger.tokenizerReady;
    s.certification.promote = false;
    s.certification.taskComplete = false;
    s.certification.verdict = "INCOMPLETE";
    s.rawrxd.shippingExecutableCertified = false;
    s.rawrxd.promote = 0;
    s.rawrxd.verdict = "INCOMPLETE";
    return s;
}

EvidenceStatus EvidenceAuthority::classifyCapabilityAbsent(const GateLedger& ledger) {
    EvidenceStatus s{};
    s.state = EvidenceState::CapabilityAbsent;
    s.capabilityAbsent = true;
    s.promoteAllowed = false;
    s.taskCompleteAllowed = false;
    s.reason = "Claim requires a capability that is absent in the authoritative source: " + ledger.gpuCapabilityReason;
    s.capabilityReason = ledger.gpuCapabilityReason;
    s.firstUnsatisfiedGate = ledger.firstUnsatisfied();
    s.execution.buildRan = ledger.configureRan && ledger.compileRan && ledger.linkRan;
    s.execution.runtimeRan = ledger.runtimeRan;
    s.execution.inferenceRan = ledger.modelLoaded && ledger.tokenizerReady;
    s.certification.promote = false;
    s.certification.taskComplete = false;
    s.certification.verdict = "CAPABILITY_ABSENT";
    s.rawrxd.shippingExecutableCertified = false;
    s.rawrxd.promote = 0;
    s.rawrxd.verdict = "CAPABILITY_ABSENT";
    return s;
}

// ---------------------------------------------------------------------------
// JSON streaming representation (for UI channel events)
// ---------------------------------------------------------------------------
std::string EvidenceAuthority::toJson(const EvidenceStatus& status) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"evidence_status\",";
    oss << "\"state\":\"" << to_string(status.state) << "\",";
    oss << "\"premature\":" << (status.premature ? "true" : "false") << ",";
    oss << "\"unsupported\":" << (status.unsupported ? "true" : "false") << ",";
    oss << "\"claim\":\"" << json_escape(status.claim) << "\",";
    oss << "\"reason\":\"" << json_escape(status.reason) << "\",";
    oss << "\"first_unsatisfied_gate\":\"" << json_escape(status.firstUnsatisfiedGate) << "\",";
    oss << "\"promote_allowed\":" << (status.promoteAllowed ? "true" : "false") << ",";
    oss << "\"task_complete_allowed\":" << (status.taskCompleteAllowed ? "true" : "false") << ",";
    oss << "\"execution\":{";
    oss << "\"build_ran\":" << (status.execution.buildRan ? "true" : "false") << ",";
    oss << "\"runtime_ran\":" << (status.execution.runtimeRan ? "true" : "false") << ",";
    oss << "\"inference_ran\":" << (status.execution.inferenceRan ? "true" : "false") << ",";
    oss << "\"certification_ran\":" << (status.execution.certificationRan ? "true" : "false");
    oss << "},";
    oss << "\"certification\":{";
    oss << "\"promote\":" << (status.certification.promote ? "true" : "false") << ",";
    oss << "\"task_complete\":" << (status.certification.taskComplete ? "true" : "false") << ",";
    oss << "\"verdict\":\"" << json_escape(status.certification.verdict) << "\"";
    oss << "},";
    oss << "\"rawrxd\":{";
    oss << "\"shipping_executable_certified\":" << (status.rawrxd.shippingExecutableCertified ? "true" : "false") << ",";
    oss << "\"promote\":" << status.rawrxd.promote << ",";
    oss << "\"verdict\":\"" << json_escape(status.rawrxd.verdict) << "\"";
    oss << "}";
    oss << "}";
    return oss.str();
}

// ---------------------------------------------------------------------------
// Compact label for collapsed UI display
// ---------------------------------------------------------------------------
std::string EvidenceAuthority::toLabel(const EvidenceStatus& status) {
    std::string label;
    if (status.premature && status.unsupported) {
        label = "Premature \u00b7 Unsupported";
    } else if (status.state == EvidenceState::Verified) {
        label = "Verified";
    } else if (status.state == EvidenceState::Incomplete) {
        label = "Incomplete";
        if (!status.firstUnsatisfiedGate.empty() && status.firstUnsatisfiedGate != "NONE") {
            label += " \u00b7 " + status.firstUnsatisfiedGate;
        }
    } else if (status.unsupported) {
        label = "Unsupported";
    } else {
        label = to_string(status.state);
    }
    return label;
}

// ---------------------------------------------------------------------------
// RawrXD-specific classifier (RAWRXD_BEACONISM_AUTHORITY_001)
// ---------------------------------------------------------------------------
EvidenceStatus classifyRawrXD(const GateLedger& ledger) {
    EvidenceAuthority auth;
    EvidenceStatus s = auth.evaluate(ledger);

    // RawrXD-specific beaconism disposition
    if (!ledger.beaconismRuntimeEvaluated) {
        s.rawrxd.beaconismTransferRequired = false;
        s.rawrxd.beaconismReason = "Beaconism runtime not evaluated; requires real causal event instrumentation";
    } else if (ledger.mirrorTerminologyAbsent && ledger.equivalentBehaviorMapped) {
        s.rawrxd.beaconismTransferRequired = false;
        s.rawrxd.beaconismReason = "Mirror terminology absent and equivalent behavior mapped; no beaconism transfer required";
    }

    // Override verdict based on RawrXD-specific first unsatisfied gate
    if (!s.firstUnsatisfiedGate.empty() && s.firstUnsatisfiedGate != "NONE") {
        s.rawrxd.verdict = "INCOMPLETE";
        s.rawrxd.promote = 0;
        s.rawrxd.shippingExecutableCertified = false;
    }

    return s;
}

} // namespace rawrxd::closure
