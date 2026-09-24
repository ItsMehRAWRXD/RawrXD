#include "CompressedKVCache.h"
#include <cmath>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <atomic>

namespace Deep2 {

// ----------------------------------------------------------------------------
// Helper: quant scale per-head
// ----------------------------------------------------------------------------
static inline void computeScaleZeroPoint(const float* src, size_t count,
                                         float& scale, float& zp) {
    float mn = src[0], mx = src[0];
    for (size_t i = 1; i < count; ++i) {
        mn = std::min(mn, src[i]);
        mx = std::max(mx, src[i]);
    }
    if (mx == mn) { scale = 1.0f; zp = 0.0f; return; }
    scale = (mx - mn) / 255.0f;
    zp = mn;
}

static inline void fp32ToQ8(const float* src, int8_t* dst, size_t count,
                            float scale, float zp) {
    for (size_t i = 0; i < count; ++i) {
        float v = (src[i] - zp) / scale;
        v = std::max(0.0f, std::min(255.0f, v));
        dst[i] = static_cast<int8_t>(std::lround(v) - 128);
    }
}

static inline void q8ToFp32(const int8_t* src, float* dst, size_t count,
                            float scale, float zp) {
    for (size_t i = 0; i < count; ++i) {
        int32_t u = static_cast<int32_t>(src[i]) + 128;
        dst[i] = static_cast<float>(u) * scale + zp;
    }
}

static inline void fp32ToQ4(const float* src, int8_t* dst, size_t count,
                            float scale, float zp) {
    // pack two nibbles per byte
    for (size_t i = 0; i < count; i += 2) {
        float v0 = (src[i] - zp) / scale;
        v0 = std::max(0.0f, std::min(15.0f, v0));
        uint8_t b0 = static_cast<uint8_t>(std::lround(v0)) & 0x0F;
        uint8_t b1 = 0;
        if (i + 1 < count) {
            float v1 = (src[i + 1] - zp) / scale;
            v1 = std::max(0.0f, std::min(15.0f, v1));
            b1 = static_cast<uint8_t>(std::lround(v1)) & 0x0F;
        }
        dst[i / 2] = static_cast<int8_t>((b1 << 4) | b0);
    }
}

static inline void q4ToFp32(const int8_t* src, float* dst, size_t count,
                            float scale, float zp) {
    for (size_t i = 0; i < count; i += 2) {
        uint8_t packed = static_cast<uint8_t>(src[i / 2]);
        uint8_t lo = packed & 0x0F;
        uint8_t hi = (packed >> 4) & 0x0F;
        dst[i] = static_cast<float>(lo) * scale + zp;
        if (i + 1 < count) dst[i + 1] = static_cast<float>(hi) * scale + zp;
    }
}

// ----------------------------------------------------------------------------
// CompressedKVCache
// ----------------------------------------------------------------------------
CompressedKVCache::CompressedKVCache(const CompressedKVConfig& cfg)
    : cfg_(cfg) {}

CompressedKVCache::~CompressedKVCache() {
    if (initialized_.load()) shutdown();
}

bool CompressedKVCache::initialize(size_t numLayers, size_t /*numHeads*/,
                                   size_t headDim, size_t maxSeqLen) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (initialized_.load()) return true;
    cfg_.numLayers = numLayers;
    cfg_.headDim = headDim;
    cfg_.maxSeqLen = maxSeqLen;
    if (cfg_.maxEntries == 0) {
        cfg_.maxEntries = numLayers * maxSeqLen * 32; // heuristic: up to 32 heads
    }
    store_.reserve(cfg_.maxEntries * 2);
    lruMap_.reserve(cfg_.maxEntries * 2);
    initialized_.store(true);
    return true;
}

void CompressedKVCache::shutdown() {
    std::lock_guard<std::mutex> lk(mtx_);
    clear();
    initialized_.store(false);
}

size_t CompressedKVCache::quantBytesPerElement() const {
    switch (cfg_.quantType) {
        case KVQuantType::KV_Q8_0: return 1;
        case KVQuantType::KV_Q4_0: return 1; // packed, but nominally 0.5; we count raw bytes
        case KVQuantType::KV_F16:  return 2;
    }
    return 1;
}

bool CompressedKVCache::encode(int layer, size_t seqPos, size_t head,
                               const float* src, size_t count) {
    if (!initialized_.load() || !src || count == 0) return false;
    auto t0 = std::chrono::high_resolution_clock::now();

    size_t bytes = count * quantBytesPerElement();
    if (cfg_.quantType == KVQuantType::KV_Q4_0) {
        bytes = (count + 1) / 2; // packed nibbles
    }

    float scale = 1.0f, zp = 0.0f;
    if (cfg_.quantType == KVQuantType::KV_Q8_0 || cfg_.quantType == KVQuantType::KV_Q4_0) {
        computeScaleZeroPoint(src, count, scale, zp);
    }

    CompressedKVEntry ent;
    ent.layer = layer;
    ent.seqPos = seqPos;
    ent.head = head;
    ent.data.resize(bytes);
    ent.scale = scale;
    ent.zeroPoint = zp;

    switch (cfg_.quantType) {
        case KVQuantType::KV_Q8_0:
            fp32ToQ8(src, ent.data.data(), count, scale, zp);
            break;
        case KVQuantType::KV_Q4_0:
            fp32ToQ4(src, ent.data.data(), count, scale, zp);
            break;
        case KVQuantType::KV_F16: {
            // simple float16-ish: just clamp to 16-bit range for now, store as uint16_t
            uint16_t* out = reinterpret_cast<uint16_t*>(ent.data.data());
            for (size_t i = 0; i < count; ++i) {
                float v = src[i];
                // naive: just reinterpret cast to fp16 pattern isn't portable,
                // so we store a scaled uint16_t representation
                int32_t iv = std::max(0, std::min(65535, static_cast<int32_t>(std::lround(v * 512.0f + 32768.0f))));
                out[i] = static_cast<uint16_t>(iv);
            }
            break;
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    recordEncodeLatency(static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()));

    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto key = std::make_tuple(layer, seqPos, head);
        auto it = store_.find(key);
        if (it != store_.end()) {
            // overwrite existing
            it->second = std::move(ent);
            auto lit = lruMap_.find(key);
            if (lit != lruMap_.end()) {
                lru_.splice(lru_.begin(), lru_, lit->second);
            }
        } else {
            evictIfNeeded();
            store_[key] = std::move(ent);
            store_[key].lastAccessEpoch = epoch_.fetch_add(1);
            lru_.push_front(key);
            lruMap_[key] = lru_.begin();
            {
                std::lock_guard<std::mutex> slk(statsMtx_);
                ++stats_.entriesTotal;
                stats_.bytesCompressed += bytes;
                stats_.bytesOriginal += count * sizeof(float);
            }
        }
    }
    return true;
}

bool CompressedKVCache::decode(int layer, size_t seqPos, size_t head,
                               float* dst, size_t count) const {
    if (!initialized_.load() || !dst || count == 0) return false;
    auto t0 = std::chrono::high_resolution_clock::now();

    std::lock_guard<std::mutex> lk(mtx_);
    auto key = std::make_tuple(layer, seqPos, head);
    auto it = store_.find(key);
    if (it == store_.end()) {
        std::lock_guard<std::mutex> slk(statsMtx_);
        ++stats_.misses;
        return false;
    }
    const CompressedKVEntry& ent = it->second;
    {
        std::lock_guard<std::mutex> slk(statsMtx_);
        ++stats_.hits;
    }
    auto lit = lruMap_.find(key);
    if (lit != lruMap_.end()) {
        const_cast<decltype(lru_)>&(lru_).splice(lru_.begin(), const_cast<decltype(lru_)>&(lru_), lit->second);
    }

    switch (cfg_.quantType) {
        case KVQuantType::KV_Q8_0:
            q8ToFp32(ent.data.data(), dst, count, ent.scale, ent.zeroPoint);
            break;
        case KVQuantType::KV_Q4_0:
            q4ToFp32(ent.data.data(), dst, count, ent.scale, ent.zeroPoint);
            break;
        case KVQuantType::KV_F16: {
            const uint16_t* in = reinterpret_cast<const uint16_t*>(ent.data.data());
            for (size_t i = 0; i < count; ++i) {
                float v = static_cast<float>(in[i]);
                dst[i] = (v - 32768.0f) / 512.0f;
            }
            break;
        }
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    const_cast<CompressedKVCache*>(this)->recordDecodeLatency(
        static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count()));
    return true;
}

bool CompressedKVCache::touch(int layer, size_t seqPos, size_t head) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto key = std::make_tuple(layer, seqPos, head);
    auto lit = lruMap_.find(key);
    if (lit == lruMap_.end()) return false;
    lru_.splice(lru_.begin(), lru_, lit->second);
    return true;
}

void CompressedKVCache::evictIfNeeded() {
    if (cfg_.maxEntries == 0) return;
    while (store_.size() >= cfg_.maxEntries && !lru_.empty()) {
        auto key = lru_.back();
        auto it = store_.find(key);
        if (it != store_.end()) {
            {
                std::lock_guard<std::mutex> slk(statsMtx_);
                ++stats_.entriesEvicted;
                stats_.bytesCompressed -= it->second.data.size();
                stats_.bytesOriginal -= it->second.data.size() * sizeof(float); // approx
            }
            store_.erase(it);
        }
        lruMap_.erase(key);
        lru_.pop_back();
    }
}

size_t CompressedKVCache::evictToFree(size_t targetBytes) {
    size_t freed = 0;
    std::lock_guard<std::mutex> lk(mtx_);
    while (freed < targetBytes && !lru_.empty()) {
        auto key = lru_.back();
        auto it = store_.find(key);
        if (it != store_.end()) {
            freed += it->second.data.size();
            {
                std::lock_guard<std::mutex> slk(statsMtx_);
                ++stats_.entriesEvicted;
                stats_.bytesCompressed -= it->second.data.size();
            }
            store_.erase(it);
        }
        lruMap_.erase(key);
        lru_.pop_back();
    }
    return freed;
}

void CompressedKVCache::clear() {
    std::lock_guard<std::mutex> lk(mtx_);
    store_.clear();
    lru_.clear();
    lruMap_.clear();
    std::lock_guard<std::mutex> slk(statsMtx_);
    stats_ = CompressedKVStats{};
    epoch_.store(1);
}

size_t CompressedKVCache::currentEntryCount() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return store_.size();
}

size_t CompressedKVCache::currentByteUsage() const {
    std::lock_guard<std::mutex> lk(mtx_);
    size_t total = 0;
    for (const auto& p : store_) total += p.second.data.size();
    return total;
}

CompressedKVStats CompressedKVCache::stats() const {
    std::lock_guard<std::mutex> slk(statsMtx_);
    return stats_;
}

void CompressedKVCache::resetStats() {
    std::lock_guard<std::mutex> slk(statsMtx_);
    stats_ = CompressedKVStats{};
}

void CompressedKVCache::recordEncodeLatency(double us) {
    std::lock_guard<std::mutex> slk(statsMtx_);
    stats_.avgEncodeUs = (stats_.avgEncodeUs * stats_.entriesTotal + us) / (stats_.entriesTotal + 1);
}

void CompressedKVCache::recordDecodeLatency(double us) {
    std::lock_guard<std::mutex> slk(statsMtx_);
    stats_.avgDecodeUs = (stats_.avgDecodeUs * stats_.hits + us) / (stats_.hits + 1);
}

bool CompressedKVCache::parityTest(const float* src, size_t count, float tolerance) {
    if (!src || count == 0 || !initialized_.load()) return false;
    std::vector<float> tmp(count);
    // choose a synthetic key
    if (!encode(0, 0, 0, src, count)) return false;
    if (!decode(0, 0, 0, tmp.data(), count)) return false;
    for (size_t i = 0; i < count; ++i) {
        float diff = std::fabs(src[i] - tmp[i]);
        if (diff > tolerance) return false;
    }
    // clean up parity test entry
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto key = std::make_tuple(0, 0, 0);
        store_.erase(key);
        lruMap_.erase(key);
        lru_.remove(key);
    }
    return true;
}

} // namespace Deep2
