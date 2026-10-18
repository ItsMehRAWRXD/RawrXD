#include "Deep2B43MoEWave.hpp"
#include <algorithm>

namespace Deep2 {

B43MoEWavePlan B43MoEWave::make(std::vector<B43Expert> ex,
                                uint32_t b0, uint32_t b1) noexcept {
    B43MoEWavePlan p{};
    std::stable_sort(ex.begin(), ex.end(),
        [](const B43Expert& a, const B43Expert& b) {
            if (a.resident != b.resident) return a.resident > b.resident;
            if (a.recentNs != b.recentNs) return a.recentNs > b.recentNs;
            return a.expert < b.expert;
        });

    uint32_t slot0=0, slot1=0;
    for (const auto& e : ex) {
        uint32_t waves = std::max(1u, e.intermediate / 1024u);
        waves = std::min(waves, 8u);
        if (e.device == 0) {
            uint32_t use = std::min(waves, b0 ? b0 : waves);
            for (uint32_t w=0; w<use; ++w) {
                uint32_t rb=(e.intermediate*w)/use;
                uint32_t re=(e.intermediate*(w+1u))/use;
                p.assignments.push_back({e.expert,0,slot0++,rb,re});
            }
            p.gpu0Waves += use;
        } else {
            uint32_t use = std::min(waves, b1 ? b1 : waves);
            for (uint32_t w=0; w<use; ++w) {
                uint32_t rb=(e.intermediate*w)/use;
                uint32_t re=(e.intermediate*(w+1u))/use;
                p.assignments.push_back({e.expert,1,slot1++,rb,re});
            }
            p.gpu1Waves += use;
        }
    }

    p.maxConcurrentExperts = std::max(1u, std::min(8u, uint32_t(ex.size())));
    return p;
}

}
