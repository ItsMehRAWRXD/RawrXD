#pragma once
#include "Deep2RooflineCommon.hpp"
#include <unordered_map>
#include <vector>

namespace Deep2::Roofline {

struct ExpertKey {
    u32 layer = 0;
    u32 expert = 0;
    bool operator==(const ExpertKey& o) const noexcept { return layer == o.layer && expert == o.expert; }
};

struct ExpertKeyHash {
    std::size_t operator()(const ExpertKey& k) const noexcept {
        return (static_cast<std::size_t>(k.layer) << 32) ^ static_cast<std::size_t>(k.expert);
    }
};

struct ResidencyResult {
    bool hit = false;
    u64 evictedBytes = 0;
    u32 evictions = 0;
};

class ExpertResidency {
public:
    explicit ExpertResidency(u64 capacityBytes = 0) : capacityBytes_(capacityBytes) {}
    void reset(u64 capacityBytes);
    ResidencyResult ensure(const ExpertKey& key, u64 bytes, u64 token, bool pin = false);
    bool contains(const ExpertKey& key) const noexcept;
    void touch(const ExpertKey& key, u64 token) noexcept;
    u64 usedBytes() const noexcept { return usedBytes_; }
    u64 capacityBytes() const noexcept { return capacityBytes_; }
    u64 hits() const noexcept { return hits_; }
    u64 misses() const noexcept { return misses_; }

private:
    struct Entry { u64 bytes = 0; u64 lastTouch = 0; u64 hits = 0; bool pinned = false; };
    using Map = std::unordered_map<ExpertKey, Entry, ExpertKeyHash>;
    Map entries_;
    u64 capacityBytes_ = 0;
    u64 usedBytes_ = 0;
    u64 hits_ = 0;
    u64 misses_ = 0;
};

} // namespace Deep2::Roofline
