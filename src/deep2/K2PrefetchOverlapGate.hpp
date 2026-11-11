#pragma once
#include "VwaPrefetchOverlap.hpp"
namespace Deep2 {
struct K2PrefetchOverlapGate {
    int measured = 0;
    int parity = 0;
    uint64_t wallUs = 0;
    uint64_t readUs = 0;
    uint64_t computeUs = 0;
};
} // namespace Deep2
