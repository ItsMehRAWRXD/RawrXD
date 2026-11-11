#pragma once
// K2Telemetry — atomic counters for K2 packed kernel certification.
// Tracks packed-vs-FP32 warehouse evidence and cache residency metrics.

#include <atomic>
#include <cstdint>
#include <cstdio>

namespace rawrxd {
namespace deep2 {

struct K2Telemetry {
    std::atomic<uint64_t> token_output_count{0};
    std::atomic<uint64_t> f32_expand_bytes{0};
    std::atomic<uint64_t> q6k_q8k_dot_entry{0};
    std::atomic<uint64_t> q4k_gemv_entry{0};
    std::atomic<uint64_t> packed_cache_hit{0};
    std::atomic<uint64_t> packed_cache_miss{0};

    void reset() noexcept {
        token_output_count.store(0);
        f32_expand_bytes.store(0);
        q6k_q8k_dot_entry.store(0);
        q4k_gemv_entry.store(0);
        packed_cache_hit.store(0);
        packed_cache_miss.store(0);
    }

    void dump() const noexcept {
        std::printf("--- K2 Telemetry ---\n");
        std::printf("  token_output_count:  %llu\n", (unsigned long long)token_output_count.load());
        std::printf("  f32_expand_bytes:    %llu\n", (unsigned long long)f32_expand_bytes.load());
        std::printf("  q6k_q8k_dot_entry:   %llu\n", (unsigned long long)q6k_q8k_dot_entry.load());
        std::printf("  q4k_gemv_entry:      %llu\n", (unsigned long long)q4k_gemv_entry.load());
        std::printf("  packed_cache_hit:    %llu\n", (unsigned long long)packed_cache_hit.load());
        std::printf("  packed_cache_miss:   %llu\n", (unsigned long long)packed_cache_miss.load());
    }

    bool certify() const noexcept {
        return token_output_count.load() > 0 &&
               f32_expand_bytes.load() == 0 &&
               q6k_q8k_dot_entry.load() > 0;
    }
};

inline K2Telemetry& GetK2Telemetry() {
    static K2Telemetry instance;
    return instance;
}

} // namespace deep2
} // namespace rawrxd