#pragma once
#include <algorithm>
#include <cstdint>
#include <vector>
namespace Deep2 {
struct SamplerAudit {
    int greedyOk = 0;
    int32_t argmax = -1;
};
inline SamplerAudit AuditGreedy(const float* logits, size_t n) {
    SamplerAudit a{};
    if (!logits || !n) return a;
    size_t best = 0;
    for (size_t i = 1; i < n; ++i)
        if (logits[i] > logits[best]) best = i;
    a.argmax = (int32_t)best;
    a.greedyOk = 1;
    return a;
}
} // namespace Deep2
