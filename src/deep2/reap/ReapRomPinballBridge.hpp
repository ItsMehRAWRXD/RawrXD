#pragma once
// REAP/ROM/Pinball opt-in adapter; C++20, no external dependencies.
// Original GGUF shards are never modified.
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Deep2::ReapRom {
struct Key {
    uint32_t layer, expert;
    bool operator==(const Key& o) const noexcept { return layer == o.layer && expert == o.expert; }
};
struct KeyHash {
    size_t operator()(Key k) const noexcept {
        return (static_cast<size_t>(k.layer) << 32) ^ k.expert;
    }
};
struct Slice {
    std::string path;
    uint64_t offset = 0, bytes = 0;
    uint32_t layer = 0, expert = 0, ggmlType = 0;
};
struct Binding {
    const void* deviceHandle = nullptr; // non-owning, backend controls lifetime
    size_t bytes = 0;
    uint64_t generation = 0;
};
struct Counters {
    uint64_t diskBytes = 0, readCalls = 0, bindingUses = 0, cacheMisses = 0, rejected = 0;
};
using Read = std::function<bool(const std::string&, uint64_t, void*, size_t)>;
using Upload = std::function<bool(const Slice&, const std::vector<uint8_t>&, Binding&)>;
using Execute = std::function<bool(const Binding&, uint32_t, uint32_t)>;

class Bridge {
public:
    Bridge(Read read, Upload upload, Execute execute)
        : read_(std::move(read)), upload_(std::move(upload)), execute_(std::move(execute)) {
        if (!read_ || !upload_ || !execute_) throw std::invalid_argument("missing callback");
    }
    void Register(Slice slice) {
        if (slice.path.empty() || !slice.bytes ||
            slice.bytes > std::numeric_limits<size_t>::max() ||
            slice.offset > std::numeric_limits<uint64_t>::max() - slice.bytes)
            throw std::invalid_argument("invalid shard slice");
        Key key{slice.layer, slice.expert};
        if (!slices_.emplace(key, std::move(slice)).second)
            throw std::invalid_argument("duplicate expert slice");
    }
    void Retain(uint32_t layer, uint32_t expert) {
        Key key{layer, expert};
        if (!slices_.contains(key)) throw std::invalid_argument("unknown expert");
        retained_.emplace(key, true);
    }
    void BindResident(uint32_t layer, uint32_t expert, Binding binding) {
        Key key{layer, expert};
        if (!retained_.contains(key) || !binding.deviceHandle || !binding.bytes)
            throw std::invalid_argument("invalid resident binding");
        resident_[key] = binding;
    }
    bool Run(uint32_t layer, uint32_t expert) {
        Key key{layer, expert};
        auto slice = slices_.find(key);
        if (slice == slices_.end() || !retained_.contains(key)) {
            ++stats_.rejected;
            return false;
        }
        auto binding = resident_.find(key);
        if (binding != resident_.end()) {
            ++stats_.bindingUses;
            return execute_(binding->second, layer, expert);
        }
        ++stats_.cacheMisses;
        const Slice& s = slice->second;
        std::vector<uint8_t> bytes(static_cast<size_t>(s.bytes));
        ++stats_.readCalls;
        if (!read_(s.path, s.offset, bytes.data(), bytes.size())) return false;
        stats_.diskBytes += s.bytes;
        Binding uploaded;
        if (!upload_(s, bytes, uploaded) || !uploaded.deviceHandle || !uploaded.bytes)
            return false;
        resident_[key] = uploaded;
        ++stats_.bindingUses;
        return execute_(uploaded, layer, expert);
    }
    // The caller must synchronize GPU work and free its own allocation.
    void ForgetAfterGpuIdle(uint32_t layer, uint32_t expert) {
        resident_.erase(Key{layer, expert});
    }
    const Counters& Stats() const noexcept { return stats_; }
private:
    Read read_;
    Upload upload_;
    Execute execute_;
    std::unordered_map<Key, Slice, KeyHash> slices_;
    std::unordered_map<Key, bool, KeyHash> retained_;
    std::unordered_map<Key, Binding, KeyHash> resident_;
    Counters stats_{};
};
} // namespace Deep2::ReapRom
