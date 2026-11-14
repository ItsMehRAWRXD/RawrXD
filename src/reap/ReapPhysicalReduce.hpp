#pragma once

// Physical REAP planner for live `--reap A/B` (source GGUF immutable).
// Installs Deep2::ReapPhysicalBank so stream routing/acquire exclude pruned
// experts. PROMOTE=0 until calibration + reference parity.

#include <cstdint>
#include <string>
#include <vector>

#include "reap/ReapRuntimePlan.hpp"

namespace RawrXD::Reap {

struct PhysicalReducePlan {
    bool enabled = false;
    bool sourceImmutable = true;
    bool writerInvoked = false;
    bool physicalRepresentation = false;
    std::string mode = "NONE";
    std::string selectionPolicy = "NONE";
    uint64_t originalModelBytes = 0;
    uint64_t originalExpertCount = 0;
    uint64_t retainedExpertsPerLayer = 0;
    uint64_t retainedExpertSlices = 0;
    uint64_t prunedParameterEstimate = 0;
    uint64_t repackedModelBytes = 0;
    uint64_t activeParametersPerToken = 0;
    uint64_t sharedBytes = 0;
    uint64_t expertBytes = 0;
    uint64_t moeLayerCount = 0;
    uint64_t topK = 0;
    std::string reason;
    std::string calibrationStatus = "NONE";
    std::string exportStatus = "NONE";
    std::string exportPath;
    std::string exportSha256;
};

bool BuildPhysicalReducePlan(const RuntimePlan& runtime,
                             PhysicalReducePlan& out,
                             std::string& error);

void ApplyPhysicalReducePlan(const PhysicalReducePlan& plan);
void ClearPhysicalReducePlan();

std::string PhysicalReduceReceiptJson(const PhysicalReducePlan& plan);

} // namespace RawrXD::Reap
