#pragma once
// Physical REAP policy (fail-closed). Distinct from residency top-k.
// P_REAP = P_shared + sum_l E_retained,l * P_expert,l
// Tip14 valued --reap <params>/<experts> remains STREAMER residency unless
// physicalExclude is staged. Offline GGUF rewrite stays on ReapMoETransformer.

#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD::Reap {

struct PhysicalTopology {
    uint64_t originalBytes = 0;
    uint64_t expertBytes = 0;
    uint64_t sharedBytes = 0;
    uint32_t originalExpertsPerLayer = 0;
    uint32_t moeLayerCount = 0;
    uint64_t logicalExpertSlices = 0;
};

struct PhysicalSelection {
    uint32_t retainedExpertsPerLayer = 0;
    std::vector<uint32_t> retainedIds; // same set every MoE layer (deterministic)
    uint64_t prunedParameterApprox = 0;
    uint64_t estimatedRepackBytes = 0;
    uint64_t activeParametersPerTokenApprox = 0;
    std::string policy = "NONE";
    std::string status = "NOT_BUILT";
    std::string reason;
};

// --reap 30GB/8 (valued): params→working-set; experts→router top-k (RESIDENCY).
// --reap --target-size 30GB --active-experts 8: disk target + retained cardinality.
inline const char* ClarifyReapSemantics() {
    return "VALUED_REAP=params_slash_experts_RESIDENCY; "
           "BARE_REAP_TARGET_SIZE=disk_bytes_PHYSICAL_CANDIDATE; "
           "ACTIVE_EXPERTS=retained_cardinality_not_top_k_alone";
}

inline bool BuildDeterministicPhysicalSelection(
    const PhysicalTopology& topo, uint32_t retained, PhysicalSelection& out) {
    out = {};
    out.policy = "POLICY_DETERMINISTIC_PREFIX";
    if (!topo.originalExpertsPerLayer || !topo.moeLayerCount || !retained) {
        out.status = "REJECTED";
        out.reason = "TOPOLOGY_OR_RETAINED_ZERO";
        return false;
    }
    if (retained > topo.originalExpertsPerLayer) {
        out.status = "REJECTED";
        out.reason = "RETAINED_EXCEEDS_ORIGINAL_EXPERTS";
        return false;
    }
    out.retainedExpertsPerLayer = retained;
    out.retainedIds.reserve(retained);
    for (uint32_t i = 0; i < retained; ++i) out.retainedIds.push_back(i);

    const uint64_t origSlices = topo.logicalExpertSlices
        ? topo.logicalExpertSlices
        : static_cast<uint64_t>(topo.originalExpertsPerLayer) * topo.moeLayerCount;
    const uint64_t keepSlices =
        static_cast<uint64_t>(retained) * topo.moeLayerCount;
    if (!origSlices || topo.expertBytes == 0) {
        out.status = "REJECTED";
        out.reason = "EXPERT_BYTE_GEOMETRY_UNKNOWN";
        return false;
    }
    const uint64_t keepExpertBytes = topo.expertBytes / origSlices * keepSlices;
    const uint64_t pruneExpertBytes = topo.expertBytes - keepExpertBytes;
    out.prunedParameterApprox = pruneExpertBytes; // byte proxy until element census
    out.estimatedRepackBytes = topo.sharedBytes + keepExpertBytes;
    // Active-per-token ≠ REAP size; leave as STUB marker via zero unless set.
    out.activeParametersPerTokenApprox = 0;
    out.status = "PLAN_READY";
    out.reason = "DETERMINISTIC_PREFIX_NOT_CALIBRATED";
    return true;
}

} // namespace RawrXD::Reap
