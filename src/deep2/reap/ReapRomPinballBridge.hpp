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
        const uint64_t packed = (static_cast<uint64_t>(k.layer) << 32) | k.expert;
        return std::hash<uint64_t>{}(packed);
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
    Bridge(Read read, Upload upload, Execute execute, size_t maxReadBytes = 256u * 1024u * 1024u)
        : read_(std::move(read)), upload_(std::move(upload)), execute_(std::move(execute)), maxReadBytes_(maxReadBytes) {
        if (!read_ || !upload_ || !execute_ || !maxReadBytes_) throw std::invalid_argument("missing callback or invalid read budget");
    }
    void Register(Slice slice) {
        if (slice.path.empty() || !slice.bytes ||
            slice.bytes > std::numeric_limits<size_t>::max() ||
            slice.bytes > maxReadBytes_ ||
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
        auto slice = slices_.find(key);
        if (slice == slices_.end() || !retained_.contains(key) ||
            !binding.deviceHandle || binding.bytes < static_cast<size_t>(slice->second.bytes))
            throw std::invalid_argument("invalid resident binding");
        if (resident_.contains(key)) throw std::logic_error("resident binding already exists; synchronize and forget before replacement");
        resident_.emplace(key, binding);
    }
    bool Run(uint32_t layer, uint32_t expert) {
        Key key{layer, expert};
        auto slice = slices_.find(key);
        if (slice == slices_.end() || !retained_.contains(key)) {
            if (stats_.rejected == std::numeric_limits<uint64_t>::max())
                throw std::overflow_error("REAP rejection counter overflow");
            ++stats_.rejected;
            return false;
        }
        auto binding = resident_.find(key);
        if (binding != resident_.end()) {
            if (stats_.bindingUses == std::numeric_limits<uint64_t>::max())
                throw std::overflow_error("REAP binding-use counter overflow");
            ++stats_.bindingUses;
            return execute_(binding->second, layer, expert);
        }
        if (stats_.cacheMisses == std::numeric_limits<uint64_t>::max())
            throw std::overflow_error("REAP cache miss counter overflow");
        ++stats_.cacheMisses;
        const Slice& s = slice->second;
        if (s.bytes > std::numeric_limits<uint64_t>::max() - stats_.diskBytes)
            throw std::overflow_error("REAP disk byte counter overflow");
        if (stats_.readCalls == std::numeric_limits<uint64_t>::max())
            throw std::overflow_error("REAP read counter overflow");
        std::vector<uint8_t> bytes(static_cast<size_t>(s.bytes));
        ++stats_.readCalls;
        if (!read_(s.path, s.offset, bytes.data(), bytes.size())) return false;
        stats_.diskBytes += s.bytes;
        Binding uploaded;
        if (!upload_(s, bytes, uploaded)) {
            if (uploaded.deviceHandle)
                throw std::runtime_error("upload failed after allocating GPU binding; caller must retire allocation");
            return false;
        }
        if (!uploaded.deviceHandle || uploaded.bytes < bytes.size())
            throw std::runtime_error("upload reported success with invalid GPU binding");
        if (stats_.bindingUses == std::numeric_limits<uint64_t>::max())
            throw std::overflow_error("REAP binding-use counter overflow");
        const auto inserted = resident_.emplace(key, uploaded).second;
        if (!inserted) throw std::logic_error("REAP resident binding changed during upload");
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
    size_t maxReadBytes_;
};
} // namespace Deep2::ReapRom
