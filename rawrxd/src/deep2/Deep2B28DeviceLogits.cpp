#include "Deep2B28DeviceLogits.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {

B28DeviceLogitsPlan B28DeviceLogits::make(const B28LogitsShape& s,
                                          double r0, double r1) noexcept {
    B28DeviceLogitsPlan p{};
    if (r0 <= 0.0) r0 = 1.0;
    if (r1 <= 0.0) r1 = 1.0;
    const double f0 = r0 / (r0 + r1);
    uint32_t split = static_cast<uint32_t>(std::llround(double(s.vocab) * f0));
    split = std::min(split, s.vocab);
    // align vocab split for vectorized block reads
    split = (split / 256u) * 256u;
    if (split == 0 && s.vocab) split = std::min(256u, s.vocab);
    if (split > s.vocab) split = s.vocab;
    p.vocab0Begin = 0;
    p.vocab0End = split;
    p.vocab1Begin = split;
    p.vocab1End = s.vocab;
    p.vectorWidth = (s.hidden % 8u == 0u) ? 8u : 4u;
    return p;
}

B28PartialArgmax B28DeviceLogits::merge(B28PartialArgmax a,
                                        B28PartialArgmax b) noexcept {
    if (b.value > a.value) return b;
    if (b.value < a.value) return a;
    return b.token < a.token ? b : a;
}

uint64_t B28DeviceLogits::avoidedD2HBytes(const B28LogitsShape& s) noexcept {
    return uint64_t(s.vocab) * sizeof(float);
}

} // namespace Deep2
