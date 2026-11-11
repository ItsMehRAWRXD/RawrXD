#include "Deep2MoEMathPlan.hpp"

namespace Deep2 {

MoEMathPlan MoEExpertMathPlanner::make(std::vector<RoutedExpert> experts) noexcept {
    MoEMathPlan p{};

    // Resident first, then slower experts earlier so their work overlaps with peers.
    std::stable_sort(experts.begin(), experts.end(),
        [](const RoutedExpert& a, const RoutedExpert& b) {
            const bool ar = a.residentBytes != 0;
            const bool br = b.residentBytes != 0;
            if (ar != br) return ar > br;
            if (a.recentNs != b.recentNs) return a.recentNs > b.recentNs;
            return a.expert < b.expert;
        });

    for (const auto& e : experts) {
        if (e.device == 0) ++p.gpu0Count;
        else if (e.device == 1) ++p.gpu1Count;
    }
    p.ordered = std::move(experts);
    return p;
}

} // namespace Deep2
