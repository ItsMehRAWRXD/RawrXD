#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>

namespace Deep2 {

struct B58RouteSample {
    uint32_t expert = 0;
    uint64_t hits = 0;
    double avgNs = 0.0;
    uint32_t device = 0;
};

struct B58RoutePlan {
    std::vector<uint32_t> hotExperts;
    std::vector<uint32_t> coldExperts;
    uint32_t prefetchTopN = 0;
    uint32_t pinTopN = 0;
    bool deterministicPlacement = true;
    bool routeAwarePrefetch = true;
    bool greedyHashStable = true;
};

class B58RouteSpecializer {
public:
    static B58RoutePlan make(std::vector<B58RouteSample>,
                             uint32_t maxPinnedExperts,
                             uint32_t maxPrefetchExperts) noexcept;
};

}
