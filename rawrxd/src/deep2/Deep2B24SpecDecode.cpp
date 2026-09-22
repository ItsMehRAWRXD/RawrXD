#include "Deep2B24SpecDecode.hpp"

namespace Deep2 {

SpecDecodePlan B24SpecDecode::make(const SpecDecodeInput& in) noexcept {
    SpecDecodePlan p{};
    if (!in.greedy || in.recentAcceptRate < 0.55 || in.draftCostFraction >= 0.40) {
        p.width = 1;
        p.enabled = false;
        return p;
    }
    uint32_t w = std::max(2u, std::min(in.requestedWidth, in.maxSafeWidth));
    if (in.recentAcceptRate >= 0.90) w = std::min(w + 2u, in.maxSafeWidth);
    else if (in.recentAcceptRate < 0.70) w = std::min(w, 3u);
    p.width = w;
    p.enabled = true;
    return p;
}

VerifyResult B24SpecDecode::verifyGreedy(const std::vector<int32_t>& draft,
                                         const std::vector<int32_t>& target) noexcept {
    VerifyResult r{};
    const size_t n = std::min(draft.size(), target.size());
    while (r.accepted < n && draft[r.accepted] == target[r.accepted]) ++r.accepted;
    r.parity = (r.accepted == n);
    return r;
}

}
