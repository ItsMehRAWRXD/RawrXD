#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>

namespace Deep2 {

struct DraftToken {
    int32_t token = -1;
    float confidence = 0.0f;
};

struct SpecDecodeInput {
    uint32_t requestedWidth = 1;
    double recentAcceptRate = 0.0;
    double draftCostFraction = 0.0;
    uint32_t maxSafeWidth = 8;
    bool greedy = true;
};

struct SpecDecodePlan {
    uint32_t width = 1;
    bool enabled = false;
    bool requireTargetVerification = true;
    bool allowPartialAccept = true;
};

struct VerifyResult {
    uint32_t accepted = 0;
    bool parity = false;
};

class B24SpecDecode {
public:
    static SpecDecodePlan make(const SpecDecodeInput&) noexcept;
    static VerifyResult verifyGreedy(const std::vector<int32_t>& draft,
                                     const std::vector<int32_t>& target) noexcept;
};

}
