#pragma once
/* MISSING15 observe/diagnostics helpers only. PRODUCT_BOUND=0 TPS_MINT=0. */
#include <cstdint>

namespace Deep2 {
namespace d2m15_obs {

inline uint32_t sample_gate(uint32_t attributable, uint64_t actual_ns) {
    return attributable != 0u && actual_ns != 0ull;
}
inline uint32_t confidence_q10(uint32_t samples, uint32_t warmup_n) {
    if (!warmup_n) return 1024u;
    if (samples >= warmup_n) return 1024u;
    return (uint32_t)(((uint64_t)samples * 1024ull) / (uint64_t)warmup_n);
}
inline uint64_t execution_cost_ns(uint64_t kernel_ns, uint64_t transfer_ns) {
    return kernel_ns + transfer_ns;
}

} // namespace d2m15_obs
} // namespace Deep2
