#pragma once
#include "Deep2ExpertResidency.hpp"
#include <unordered_map>

namespace Deep2::Roofline {

class PredictiveRouter {
public:
    void observe(u32 layer, const std::vector<u32>& experts);
    std::vector<u32> predict(u32 layer, u32 maxExperts) const;
    void reset();

private:
    struct LayerStats {
        std::unordered_map<u32, u64> frequency;
        std::vector<u32> last;
    };
    std::unordered_map<u32, LayerStats> layers_;
};

} // namespace Deep2::Roofline
