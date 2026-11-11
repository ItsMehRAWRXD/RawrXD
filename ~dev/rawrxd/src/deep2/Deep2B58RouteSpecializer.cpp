#include "Deep2B58RouteSpecializer.hpp"

namespace Deep2 {

B58RoutePlan B58RouteSpecializer::make(std::vector<B58RouteSample> s,
                                       uint32_t maxPinned,
                                       uint32_t maxPrefetch) noexcept {
    B58RoutePlan p{};
    std::stable_sort(s.begin(), s.end(),
        [](const B58RouteSample& a, const B58RouteSample& b) {
            if (a.hits != b.hits) return a.hits > b.hits;
            if (a.avgNs != b.avgNs) return a.avgNs > b.avgNs;
            return a.expert < b.expert;
        });

    p.pinTopN = std::min<uint32_t>(maxPinned, static_cast<uint32_t>(s.size()));
    p.prefetchTopN = std::min<uint32_t>(maxPrefetch, static_cast<uint32_t>(s.size()));

    for (size_t i=0;i<s.size();++i) {
        if (i < p.pinTopN) p.hotExperts.push_back(s[i].expert);
        else p.coldExperts.push_back(s[i].expert);
    }
    return p;
}

}
