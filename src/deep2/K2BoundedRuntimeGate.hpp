#pragma once
#include <cstdint>
namespace Deep2 {
struct K2BoundedRuntimeGate {
    uint64_t maxRssBytes = 0;
    uint64_t wallMs = 0;
    int bounded = 0;
};
inline bool K2RuntimeWithinBound(uint64_t used, uint64_t cap) {
    return used > 0 && used <= cap;
}
} // namespace Deep2
