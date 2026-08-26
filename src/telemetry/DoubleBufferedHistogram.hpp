#pragma once

#include <atomic>
#include <array>
#include <cstdint>
#include <cstddef>
#include <algorithm>

#if defined(_MSC_VER)
  #include <intrin.h>
#endif

template <uint32_t SubBucketBits = 3>
class HighPrecisionBucketMapper {
public:
    static constexpr uint32_t M = SubBucketBits;
    static constexpr uint32_t S = 1U << M;
    static constexpr uint32_t MASK = S - 1U;
    static constexpr size_t NUM_BUCKETS = S + ((64 - M) << M);

    static inline uint32_t latency_to_bucket(uint64_t ns) noexcept {
        if (ns < S) return static_cast<uint32_t>(ns);
#if defined(_MSC_VER)
        const uint32_t lz = static_cast<uint32_t>(_lzcnt_u64(ns));
#else
        const uint32_t lz = static_cast<uint32_t>(__builtin_clzll(ns));
#endif
        const uint32_t k = 63U - lz;
        const uint32_t shift = k - M;
        const uint32_t sub = static_cast<uint32_t>(ns >> shift) & MASK;
        return ((k - M) << M) + sub + S;
    }

    static inline uint64_t bucket_to_latency(uint32_t bucket) noexcept {
        if (bucket < S) return static_cast<uint64_t>(bucket);
        const uint32_t adjusted = bucket - S;
        const uint32_t major = adjusted >> M;
        const uint32_t sub = adjusted & MASK;
        const uint32_t k = major + M;
        const uint64_t base = 1ULL << k;
        const uint64_t step = 1ULL << (k - M);
        return base + static_cast<uint64_t>(sub + 1) * step;
    }
};

class DoubleBufferedHistogram {
public:
    static constexpr size_t NUM_BUCKETS = 64;

    struct Percentiles {
        uint64_t p50_ns{0};
        uint64_t p90_ns{0};
        uint64_t p99_ns{0};
        uint64_t p999_ns{0};
        uint64_t total_samples{0};
    };

    DoubleBufferedHistogram() {
        clear_buffer(0);
        clear_buffer(1);
    }

    inline void record(uint64_t latency_ns) noexcept {
        const uint32_t bucket = latency_to_bucket(latency_ns);
        const uint32_t active_idx = active_buffer_.load(std::memory_order_relaxed);
        buffers_[active_idx][bucket].fetch_add(1, std::memory_order_relaxed);
    }

    Percentiles swap_and_evaluate() noexcept {
        const uint32_t inactive_idx = active_buffer_.fetch_xor(1, std::memory_order_acq_rel);

        uint64_t total_samples = 0;
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            total_samples += buffers_[inactive_idx][i].load(std::memory_order_relaxed);
        }

        Percentiles result{};
        result.total_samples = total_samples;

        if (total_samples == 0) {
            return result;
        }

        const uint64_t target_p50  = static_cast<uint64_t>(total_samples * 0.50);
        const uint64_t target_p90  = static_cast<uint64_t>(total_samples * 0.90);
        const uint64_t target_p99  = static_cast<uint64_t>(total_samples * 0.99);
        const uint64_t target_p999 = static_cast<uint64_t>(total_samples * 0.999);

        uint64_t accumulated = 0;

        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            const uint64_t count = buffers_[inactive_idx][i].load(std::memory_order_relaxed);
            accumulated += count;

            if (!result.p50_ns  && accumulated >= target_p50)  result.p50_ns  = bucket_to_latency(i);
            if (!result.p90_ns  && accumulated >= target_p90)  result.p90_ns  = bucket_to_latency(i);
            if (!result.p99_ns  && accumulated >= target_p99)  result.p99_ns  = bucket_to_latency(i);
            if (!result.p999_ns && accumulated >= target_p999) result.p999_ns = bucket_to_latency(i);
        }

        clear_buffer(inactive_idx);

        return result;
    }

private:
    static inline uint32_t latency_to_bucket(uint64_t latency_ns) noexcept {
        if (latency_ns == 0) return 0;
#if defined(_MSC_VER)
        return 64 - static_cast<uint32_t>(_lzcnt_u64(latency_ns));
#else
        return 64 - static_cast<uint32_t>(__builtin_clzll(latency_ns));
#endif
    }

    static inline uint64_t bucket_to_latency(size_t bucket_idx) noexcept {
        if (bucket_idx == 0) return 0;
        return 1ULL << (bucket_idx - 1);
    }

    void clear_buffer(uint32_t buffer_idx) noexcept {
        for (size_t i = 0; i < NUM_BUCKETS; ++i) {
            buffers_[buffer_idx][i].store(0, std::memory_order_relaxed);
        }
    }

    alignas(64) std::atomic<uint32_t> active_buffer_{0};

    using BucketArray = std::array<std::atomic<uint64_t>, NUM_BUCKETS>;
    alignas(64) BucketArray buffers_[2];
};
