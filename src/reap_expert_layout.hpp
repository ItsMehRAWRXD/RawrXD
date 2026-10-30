#pragma once

#include <cstdint>
#include <string>

namespace RawrXD::Reap {

enum class ExpertLayoutKind : int {
    Absent = 0,
    DeepseekTriplet = 1,
    PairUpDown = 2,
    InvalidTriplet = 3
};

struct ExpertLayoutDecision {
    ExpertLayoutKind kind = ExpertLayoutKind::Absent;
    int64_t experts = 0;
    const char* reason = "";
};

// Presence plus the last shape axis. A gate-less up/down pair stays rejected.
inline ExpertLayoutDecision ClassifyExpertProjections(
    bool gate, bool up, bool down,
    bool gateShape, bool upShape, bool downShape,
    int64_t gateBack, int64_t upBack, int64_t downBack) {
    ExpertLayoutDecision decision;
    if (!gate && !up && !down) return decision;
    if (!gate && up && down && upShape && downShape && upBack > 0 && upBack == downBack) {
        decision.kind = ExpertLayoutKind::PairUpDown;
        decision.experts = upBack;
        decision.reason = "REAP_EXPERT_LAYOUT_UNSUPPORTED";
        return decision;
    }
    if (gate && up && down && gateShape && upShape && downShape &&
        gateBack > 0 && gateBack == upBack && gateBack == downBack) {
        decision.kind = ExpertLayoutKind::DeepseekTriplet;
        decision.experts = gateBack;
        decision.reason = "REAP_EXPERT_LAYOUT_TRIPLET";
        return decision;
    }
    decision.kind = ExpertLayoutKind::InvalidTriplet;
    decision.reason = "INVALID_EXPERT_TRIPLET";
    return decision;
}

inline std::string LayoutRejection(const ExpertLayoutDecision& decision,
                                   uint32_t layer, const std::string& arch) {
    if (decision.kind == ExpertLayoutKind::PairUpDown) {
        return std::string(decision.reason) +
               " layout=pair_up_down_exps_without_gate_exps layer=" +
               std::to_string(layer) + " experts=" + std::to_string(decision.experts) +
               " arch=" + arch;
    }
    if (decision.kind == ExpertLayoutKind::InvalidTriplet) {
        return std::string(decision.reason) + " layer=" + std::to_string(layer) +
               " arch=" + arch;
    }
    return {};
}

} // namespace RawrXD::Reap
