/* K2LivePathTensorCache — Live tensor cache for K2 model weights
 * Stores packed weight tensors with format tags, no FP32 warehouse expansion.
 */
#pragma once

#include <unordered_map>
#include <string>
#include <cstdint>
#include <cstddef>
#include <vector>
#include "K2Telemetry.hpp"

namespace rawrxd {
namespace deep2 {

struct CachedTensor {
    std::vector<uint8_t> data;
    uint32_t format = 0;  // GGML format enum (14 = Q6_K)
    size_t size_bytes = 0;
};

class K2LivePathTensorCache {
public:
    // Put tensor into cache with format tag
    void put(const std::string& key, const void* data, size_t size_bytes, uint32_t format) {
        CachedTensor tensor;
        tensor.data.resize(size_bytes);
        std::memcpy(tensor.data.data(), data, size_bytes);
        tensor.format = format;
        tensor.size_bytes = size_bytes;
        cache_[key] = std::move(tensor);
    }

    // Get tensor by key (returns nullptr if not found)
    const void* get(const std::string& key) const {
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            auto& tel = GetK2Telemetry();
            tel.packed_cache_miss.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        auto& tel = GetK2Telemetry();
        tel.packed_cache_hit.fetch_add(1, std::memory_order_relaxed);
        return it->second.data.data();
    }

    // Get tensor by key with format output
    const void* get(const std::string& key, uint32_t& out_format) const {
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            out_format = 0;
            auto& tel = GetK2Telemetry();
            tel.packed_cache_miss.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        out_format = it->second.format;
        auto& tel = GetK2Telemetry();
        tel.packed_cache_hit.fetch_add(1, std::memory_order_relaxed);
        return it->second.data.data();
    }

    // Check if key exists
    bool contains(const std::string& key) const {
        return cache_.find(key) != cache_.end();
    }

    // Get number of cached tensors
    size_t count() const {
        return cache_.size();
    }

    // Clear cache
    void clear() {
        cache_.clear();
    }

    // Get total bytes stored
    size_t total_bytes() const {
        size_t total = 0;
        for (const auto& kv : cache_) {
            total += kv.second.size_bytes;
        }
        return total;
    }

private:
    std::unordered_map<std::string, CachedTensor> cache_;
};

} // namespace deep2
} // namespace rawrxd