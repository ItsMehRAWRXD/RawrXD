#pragma once

#include <atomic>
#include <array>
#include <algorithm>
#include <cstdint>
#include <cstddef>
#include <vector>

template <size_t Capacity = 65536>
class LockFreeLatencyTracker {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of 2");

public:
    struct Percentiles {
        uint64_t p50{0};
        uint64_t p90{0};
        uint64_t p99{0};
        uint64_t p999{0};
        uint64_t max{0};
        size_t samples_count{0};
    };

    LockFreeLatencyTracker() {
        for (auto& slot : buffer_) {
            slot.store(0, std::memory_order_relaxed);
        }
    }

    // ====================================================================
    // HOT PATH: Called directly inside inference / kernel dispatch loops
    // Costs ~3-5 CPU cycles. Zero locks, zero allocations.
    // ====================================================================
    inline void record(uint64_t latency_ns) noexcept {
        const size_t idx = write_head_.fetch_add(1, std::memory_order_relaxed);
        buffer_[idx & MASK].store(latency_ns, std::memory_order_relaxed);
    }

    // ====================================================================
    // COLD PATH: Called by background telemetry / Deep2 scheduler thread
    // Snapshots recent ring buffer window into a caller-owned scratch buffer.
    // ====================================================================
    Percentiles compute_percentiles(std::vector<uint64_t>& scratch_buffer) noexcept {
        const size_t current_head = write_head_.load(std::memory_order_relaxed);
        size_t tail = read_tail_;

        size_t count = current_head - tail;
        if (count == 0) return {};

        if (count > Capacity) {
            count = Capacity;
            tail = current_head - Capacity;
        }

        scratch_buffer.clear();
        if (scratch_buffer.capacity() < count) {
            scratch_buffer.reserve(Capacity);
        }

        for (size_t i = 0; i < count; ++i) {
            uint64_t val = buffer_[(tail + i) & MASK].load(std::memory_order_relaxed);
            if (val > 0) {
                scratch_buffer.push_back(val);
            }
        }

        read_tail_ = current_head;

        if (scratch_buffer.empty()) return {};

        Percentiles stats;
        stats.samples_count = scratch_buffer.size();

        auto get_quantile = [&](double q) -> uint64_t {
            size_t target_idx = static_cast<size_t>(q * (stats.samples_count - 1));
            std::nth_element(scratch_buffer.begin(),
                             scratch_buffer.begin() + target_idx,
                             scratch_buffer.end());
            return scratch_buffer[target_idx];
        };

        stats.p50  = get_quantile(0.50);
        stats.p90  = get_quantile(0.90);
        stats.p99  = get_quantile(0.99);
        stats.p999 = get_quantile(0.999);

        stats.max = *std::max_element(scratch_buffer.begin(), scratch_buffer.end());

        return stats;
    }

private:
    static constexpr size_t MASK = Capacity - 1;

    alignas(64) std::atomic<size_t> write_head_{0};
    alignas(64) size_t read_tail_{0};

    alignas(64) std::array<std::atomic<uint64_t>, Capacity> buffer_;
};

// Convenience alias for PCIe stall tracking
using PCIeStallTracker = LockFreeLatencyTracker<65536>;
