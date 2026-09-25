// RAWRXD_BEACONISM_99_WORK_AVOID_001
#include "beaconism_99.hpp"

#include <cstring>
#include <algorithm>
#include <limits>

namespace rawrxd::beaconism {

static inline uint64_t rotl64(uint64_t x, unsigned r) noexcept {
    return (x << r) | (x >> (64u - r));
}

static inline uint64_t mix64(uint64_t x) noexcept {
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

BeaconReplayCache::BeaconReplayCache(size_t max_bytes)
    : max_bytes_(max_bytes ? max_bytes : 1) {}

Hash128 BeaconReplayCache::hash_bytes(const void* data, size_t bytes, uint64_t seed) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    uint64_t a = mix64(0x243f6a8885a308d3ULL ^ seed ^ uint64_t(bytes));
    uint64_t b = mix64(0x13198a2e03707344ULL + seed + uint64_t(bytes << 1));

    size_t i = 0;
    while (i + 16 <= bytes) {
        uint64_t x = 0, y = 0;
        std::memcpy(&x, p + i, 8);
        std::memcpy(&y, p + i + 8, 8);
        a = mix64(a ^ x ^ rotl64(y, 17));
        b = mix64(b ^ y ^ rotl64(x, 31));
        i += 16;
    }

    uint64_t tail0 = 0, tail1 = 0;
    size_t rem = bytes - i;
    if (rem) {
        size_t n0 = rem > 8 ? 8 : rem;
        std::memcpy(&tail0, p + i, n0);
        if (rem > 8) std::memcpy(&tail1, p + i + 8, rem - 8);
    }

    a = mix64(a ^ tail0 ^ uint64_t(rem));
    b = mix64(b ^ tail1 ^ rotl64(uint64_t(rem), 13));
    a ^= rotl64(b, 23);
    b ^= rotl64(a, 41);
    return {mix64(a), mix64(b)};
}

uint64_t BeaconReplayCache::checksum64(const void* data, size_t bytes, uint64_t seed) noexcept {
    Hash128 h = hash_bytes(data, bytes, seed ^ 0xa5a5a5a5d3c1b2e7ULL);
    return mix64(h.lo ^ rotl64(h.hi, 29) ^ uint64_t(bytes));
}

uint64_t BeaconReplayCache::make_desc_hash(const SegmentDesc& d) const noexcept {
    uint64_t x = mix64(d.model_id);
    x ^= mix64(d.model_revision + 0x9e3779b97f4a7c15ULL);
    x ^= mix64((uint64_t(d.segment_begin) << 32) | d.segment_end);
    x ^= mix64(d.config_id);
    return mix64(x);
}

bool BeaconReplayCache::desc_equal(const SegmentDesc& a, const SegmentDesc& b) const noexcept {
    return a.model_id == b.model_id &&
           a.model_revision == b.model_revision &&
           a.segment_begin == b.segment_begin &&
           a.segment_end == b.segment_end &&
           a.config_id == b.config_id;
}

void BeaconReplayCache::evict_to_fit(size_t incoming_bytes) noexcept {
    if (incoming_bytes > max_bytes_) {
        entries_.clear();
        live_bytes_ = 0;
        return;
    }
    while (live_bytes_ + incoming_bytes > max_bytes_ && !entries_.empty()) {
        auto it = std::min_element(entries_.begin(), entries_.end(),
            [](const Entry& a, const Entry& b) { return a.age < b.age; });
        live_bytes_ -= it->output.size();
        entries_.erase(it);
    }
}

bool BeaconReplayCache::try_replay(const SegmentDesc& desc,
                                   const void* input, size_t input_bytes,
                                   void* output, size_t output_bytes) noexcept {
    ++stats_.lookups;
    stats_.nominal_work_units += desc.nominal_work_units;

    if ((!input && input_bytes) || (!output && output_bytes)) {
        ++stats_.misses;
        return false;
    }

    const Hash128 ih = hash_bytes(input, input_bytes, make_desc_hash(desc));
    const uint64_t ic = checksum64(input, input_bytes, desc.config_id);

    for (auto& e : entries_) {
        if (!(e.input_hash == ih)) continue;

        if (!desc_equal(e.desc, desc)) {
            ++stats_.collision_rejects;
            continue;
        }
        if (e.input_check != ic) {
            ++stats_.collision_rejects;
            continue;
        }
        if (e.output.size() != output_bytes) {
            ++stats_.validation_rejects;
            continue;
        }

        const uint64_t oc = checksum64(e.output.data(), e.output.size(),
                                       e.desc.model_id ^ e.desc.model_revision);
        if (oc != e.output_check) {
            ++stats_.validation_rejects;
            continue;
        }

        if (output_bytes) std::memcpy(output, e.output.data(), output_bytes);
        e.age = ++age_counter_;
        ++stats_.hits;
        stats_.avoided_work_units += desc.nominal_work_units;
        return true;
    }

    ++stats_.misses;
    return false;
}

bool BeaconReplayCache::commit(const SegmentDesc& desc,
                               const void* input, size_t input_bytes,
                               const void* output, size_t output_bytes) noexcept {
    if ((!input && input_bytes) || (!output && output_bytes)) return false;
    if (output_bytes > max_bytes_) return false;

    const Hash128 ih = hash_bytes(input, input_bytes, make_desc_hash(desc));
    const uint64_t ic = checksum64(input, input_bytes, desc.config_id);
    const uint64_t oc = checksum64(output, output_bytes,
                                   desc.model_id ^ desc.model_revision);

    // Replace exact key if already present.
    for (auto& e : entries_) {
        if (e.input_hash == ih && e.input_check == ic && desc_equal(e.desc, desc)) {
            live_bytes_ -= e.output.size();
            evict_to_fit(output_bytes);
            e.output.resize(output_bytes);
            if (output_bytes) std::memcpy(e.output.data(), output, output_bytes);
            e.output_check = oc;
            e.age = ++age_counter_;
            live_bytes_ += output_bytes;
            ++stats_.commits;
            return true;
        }
    }

    evict_to_fit(output_bytes);
    Entry e{};
    e.desc = desc;
    e.input_hash = ih;
    e.input_check = ic;
    e.output_check = oc;
    e.age = ++age_counter_;
    e.output.resize(output_bytes);
    if (output_bytes) std::memcpy(e.output.data(), output, output_bytes);
    live_bytes_ += output_bytes;
    entries_.push_back(std::move(e));
    ++stats_.commits;
    return true;
}

void BeaconReplayCache::account_executed(uint64_t nominal_work_units) noexcept {
    stats_.executed_work_units += nominal_work_units;
}

void BeaconReplayCache::clear() noexcept {
    entries_.clear();
    live_bytes_ = 0;
    age_counter_ = 0;
    stats_ = {};
}

Stats BeaconReplayCache::stats() const noexcept {
    Stats s = stats_;
    if (s.lookups) s.hit_rate_pct = 100.0 * double(s.hits) / double(s.lookups);
    if (s.nominal_work_units) {
        s.work_avoided_pct =
            100.0 * double(s.avoided_work_units) / double(s.nominal_work_units);
    }
    return s;
}

} // namespace rawrxd::beaconism
