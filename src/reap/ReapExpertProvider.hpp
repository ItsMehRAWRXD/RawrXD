// ReapExpertProvider.hpp — RAWRXD S01 (Streaming foundation)
// Demand-driven expert acquisition from stacked expert tensors, using the shared
// slicing core. Acquires ONE expert per call (no full expert-bank materialization).
// Storage-independent; reusable by Streaming residency/paging.
#pragma once
#include "reap/ReapTensorSlice.hpp"
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>

namespace RawrXD::Reap {

class ExpertProvider {
public:
    // Register a stacked expert tensor (descriptor + source buffer). Source must
    // outlive acquisitions (caller owns the checkpoint buffer).
    void Register(uint32_t layer, const SliceTensorDesc& t, const uint8_t* src) {
        tensors_[layer] = {t, src};
    }
    // Acquire one expert's bytes into dst (demand-driven). Returns false on
    // invalid layer/expert/buffer. Copies exactly one expert slice.
    bool Acquire(uint32_t layer, uint32_t expert, uint8_t* dst, size_t dstBytes) {
        auto it = tensors_.find(layer);
        if (it == tensors_.end() || !it->second.src || !dst) return false;
        ExpertSelection sel{{layer, {expert}}};
        SliceResult r = SliceExperts(it->second.desc, layer, sel);
        if (!r.ok || r.ranges.empty()) return false;
        const auto& rng = r.ranges[0];
        if (rng.second > dstBytes) return false;
        std::memcpy(dst, it->second.src + rng.first, (size_t)rng.second);
        acquisitions_ += rng.second;
        ++acquires_;
        return true;
    }
    uint64_t AcquiredBytes() const noexcept { return acquisitions_; }
    uint64_t AcquireCount() const noexcept { return acquires_; }
private:
    struct Entry { SliceTensorDesc desc; const uint8_t* src = nullptr; };
    std::unordered_map<uint32_t, Entry> tensors_;
    uint64_t acquisitions_ = 0, acquires_ = 0;
};

} // namespace RawrXD::Reap