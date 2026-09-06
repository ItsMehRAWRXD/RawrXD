// ============================================================================
// ExecutionPolicyApply.hpp — enforce policy on IDE Elastic + optional MARS
// ============================================================================
#pragma once

#include "PlacementPlan.hpp"
#include <string>

namespace Deep2 {
class Deep2Engine;
class ElasticResidencyManager;
namespace MARS {
class MARSController;
}

namespace Exec {

PlacementApplyReport& LastApplyReport();
const PlacementPlan& LastPlacementPlan();

DeviceKind PlannedDeviceForTensor(const ExecutionPolicy& policy,
                                  const std::string& name,
                                  int layer);

// Stamp + promote Elastic residency to match ActivePolicy. Fills report predicates.
bool ApplyPlacementToElastic(ElasticResidencyManager& elastic,
                             int nLayers,
                             PlacementApplyReport& report);

bool ObserveElasticMatchesPlan(ElasticResidencyManager& elastic,
                               PlacementApplyReport& report);

// Optional MARS path (Deep2Engine after loadModel).
PlacementApplyReport ApplyExecutionPolicyToEngine(
    Deep2Engine& engine,
    const std::string& modelPath,
    const std::string& modelFingerprint = {});

bool ObserveMatchesPlan(MARS::MARSController& mars,
                        const PlacementPlan& plan,
                        PlacementApplyReport& report);

// IDE loader seam: call after Elastic register, before MODEL_READY.
PlacementApplyReport EnforcePolicyOnIdeLoad(
    ElasticResidencyManager* elastic,
    const std::string& modelPath,
    int nLayers,
    uint32_t tensorCount);

} // namespace Exec
} // namespace Deep2
