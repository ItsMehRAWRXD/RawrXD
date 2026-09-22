#pragma once
/* ElasticResidencyManager — representation-aware residency/prefetch surface.
 * Standalone builds use the inline header implementation; the product tree
 * may override with a full-featured translation unit. */
#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
class ElasticResidencyManager {
public:
    // Layer tensor forecast hook used by the multi-GPU ownership handoff.
    // Standalone: predictive planning is a no-op that always reports ready.
    void PredictLayerNeeds(uint32_t /*layer*/,
                           const std::vector<std::string>* /*names*/,
                           size_t /*count*/) {}

    // Observed prefetch hit rate in percent (0..100).
    double PrefetchHitRatePct() const { return 0.0; }
};
} // namespace Deep2
