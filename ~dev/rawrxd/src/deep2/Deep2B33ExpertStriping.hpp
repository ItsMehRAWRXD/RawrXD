#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>

namespace Deep2 {

struct B33DeviceRate {
    double bytesPerNs = 0.0;
    uint64_t freeVramBytes = 0;
};

struct B33ExpertDesc {
    uint32_t expert = 0;
    uint64_t bytes = 0;
    double recentNs = 0.0;
    bool hot = false;
};

struct B33Placement {
    uint32_t expert = 0;
    uint32_t device = 0;
    uint64_t bytes = 0;
};

struct B33StripePlan {
    std::vector<B33Placement> placement;
    uint64_t gpu0Bytes = 0;
    uint64_t gpu1Bytes = 0;
    uint32_t gpu0Experts = 0;
    uint32_t gpu1Experts = 0;
    bool stableOwnership = true;
    bool peerCopyOnHit = false;
};

class B33ExpertStriping {
public:
    static B33StripePlan make(std::vector<B33ExpertDesc>,
                              const B33DeviceRate&,
                              const B33DeviceRate&) noexcept;
};

} // namespace Deep2
