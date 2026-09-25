#pragma once
// RAWRXD_BEACONISM_99_WORK_AVOID_001
// Dependency-free C++20 replay cache for deterministic inference segments.
// Windows/native STL only. No external libraries.
//
// Design contract:
//   * A segment may be skipped only after an exact model/config/segment/key match.
//   * Cached payload is validated before replay.
//   * Miss/collision/corruption => caller executes the real segment.
//   * "work avoided" is accounted from caller-supplied nominal work units.
//   * 99% is a target ceiling, not a fabricated guarantee.
//
// Typical use:
//   if (beacon.try_replay(desc, input_bytes, input_size, out, out_bytes)) {
//       // segment skipped safely
//   } else {
//       run_real_segment(...);
//       beacon.commit(desc, input_bytes, input_size, out, out_bytes);
//   }

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace rawrxd::beaconism {

struct Hash128 {
    uint64_t lo{};
    uint64_t hi{};
    bool operator==(const Hash128& r) const noexcept { return lo == r.lo && hi == r.hi; }
};

struct SegmentDesc {
    uint64_t model_id{};
    uint64_t model_revision{};
    uint32_t segment_begin{};
    uint32_t segment_end{};
    uint64_t config_id{};          // quant mode, rope mode, context geometry, etc.
    uint64_t nominal_work_units{}; // FLOPs/bytes/weighted units for accounting
};

struct Stats {
    uint64_t lookups{};
    uint64_t hits{};
    uint64_t misses{};
    uint64_t collision_rejects{};
    uint64_t validation_rejects{};
    uint64_t commits{};
    uint64_t nominal_work_units{};
    uint64_t executed_work_units{};
    uint64_t avoided_work_units{};
    double hit_rate_pct{};
    double work_avoided_pct{};
};

class BeaconReplayCache {
public:
    explicit BeaconReplayCache(size_t max_bytes = 512ull * 1024ull * 1024ull);

    bool try_replay(const SegmentDesc& desc,
                    const void* input, size_t input_bytes,
                    void* output, size_t output_bytes) noexcept;

    bool commit(const SegmentDesc& desc,
                const void* input, size_t input_bytes,
                const void* output, size_t output_bytes) noexcept;

    // Call on a miss after the real segment ran, so accounting is exact.
    void account_executed(uint64_t nominal_work_units) noexcept;

    void clear() noexcept;
    Stats stats() const noexcept;

    static Hash128 hash_bytes(const void* data, size_t bytes, uint64_t seed = 0) noexcept;
    static uint64_t checksum64(const void* data, size_t bytes, uint64_t seed = 0) noexcept;

private:
    struct Entry {
        SegmentDesc desc{};
        Hash128 input_hash{};
        uint64_t input_check{};
        uint64_t output_check{};
        uint64_t age{};
        std::vector<uint8_t> output;
    };

    uint64_t make_desc_hash(const SegmentDesc& d) const noexcept;
    bool desc_equal(const SegmentDesc& a, const SegmentDesc& b) const noexcept;
    void evict_to_fit(size_t incoming_bytes) noexcept;

    size_t max_bytes_{};
    size_t live_bytes_{};
    uint64_t age_counter_{};
    std::vector<Entry> entries_;
    mutable Stats stats_{};
};

} // namespace rawrxd::beaconism
