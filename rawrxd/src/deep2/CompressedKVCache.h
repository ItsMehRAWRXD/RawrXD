#pragma once
// ============================================================================
// CompressedKVCache — Real compressed KV storage with encode/decode,
// capacity accounting, eviction, parity test.
// ============================================================================
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <mutex>
#include <unordered_map>
#include <list>

namespace Deep2 {

enum class KVQuantType : uint8_t {
    KV_Q8_0 = 0,
    KV_Q4_0 = 1,
    KV_F16  = 2
};

struct CompressedKVConfig {
    size_t maxEntries = 0;       // 0 = auto from numLayers * maxSeq
    size_t headDim = 0;
    size_t numLayers = 0;
    size_t maxSeqLen = 0;
    KVQuantType quantType = KVQuantType::KV_Q8_0;
    float compressionRatio = 2.0f; // nominal: FP32 → Q8_0 = 4x, clamped
};

struct CompressedKVEntry {
    int layer = 0;
    size_t seqPos = 0;
    size_t head = 0;
    std::vector<int8_t> data;     // quantized bytes
    float scale = 1.0f;
    float zeroPoint = 0.0f;
    uint64_t lastAccessEpoch = 0;
};

struct CompressedKVStats {
    uint64_t entriesTotal = 0;
    uint64_t entriesEvicted = 0;
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t bytesCompressed = 0;
    uint64_t bytesOriginal = 0;
    double avgEncodeUs = 0.0;
    double avgDecodeUs = 0.0;
};

class CompressedKVCache {
public:
    CompressedKVCache() = default;
    explicit CompressedKVCache(const CompressedKVConfig& cfg);
    ~CompressedKVCache();

    CompressedKVCache(const CompressedKVCache&) = delete;
    CompressedKVCache& operator=(const CompressedKVCache&) = delete;

    bool initialize(size_t numLayers, size_t numHeads, size_t headDim, size_t maxSeqLen);
    bool isInitialized() const { return initialized_; }
    void shutdown();

    // Encode: compress FP32 KV head → internal entry
    bool encode(int layer, size_t seqPos, size_t head,
                const float* src, size_t count);

    // Decode: decompress entry → FP32 KV head
    bool decode(int layer, size_t seqPos, size_t head,
                float* dst, size_t count) const;

    // Touch: update LRU order without decode
    bool touch(int layer, size_t seqPos, size_t head);

    // Evict: remove oldest entries to free capacity
    size_t evictToFree(size_t targetBytes);

    // Clear all entries
    void clear();

    // Capacity / accounting
    size_t currentEntryCount() const;
    size_t currentByteUsage() const;
    size_t maxCapacityEntries() const { return cfg_.maxEntries; }

    // Stats
    CompressedKVStats stats() const;
    void resetStats();

    // Parity test: encode then decode a buffer, verify within tolerance
    bool parityTest(const float* src, size_t count, float tolerance = 1e-3f);

private:
    CompressedKVConfig cfg_;
    std::atomic<bool> initialized_{false};
    mutable std::mutex mtx_;

    // LRU: front = most recent, back = oldest
    std::list<std::tuple<int, size_t, size_t>> lru_;
    struct KeyHash {
        size_t operator()(const std::tuple<int, size_t, size_t>& k) const noexcept {
            size_t h1 = std::hash<int>{}(std::get<0>(k));
            size_t h2 = std::hash<size_t>{}(std::get<1>(k));
            size_t h3 = std::hash<size_t>{}(std::get<2>(k));
            return h1 ^ (h2 << 1) ^ (h3 << 2);
        }
    };
    std::unordered_map<std::tuple<int, size_t, size_t>, CompressedKVEntry, KeyHash> store_;
    std::unordered_map<std::tuple<int, size_t, size_t>, decltype(lru_)::iterator, KeyHash> lruMap_;

    mutable std::mutex statsMtx_;
    CompressedKVStats stats_;
    std::atomic<uint64_t> epoch_{1};

    size_t quantBytesPerElement() const;
    void evictIfNeeded();
    void recordEncodeLatency(double us);
    void recordDecodeLatency(double us);
};

} // namespace Deep2
