#pragma once
// Native, dependency-free, chunked byte residency cache.
// Lossless RLE is selected per chunk only when it is smaller than raw bytes.
// Callers request byte ranges; only intersecting chunks are materialized.
// This cache does not own the source mapping: owners may release it only after
// successful admission and after all readers have stopped using that mapping.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Deep2 {

class TensorResidencyCache {
public:
    enum class Encoding : uint8_t { Raw = 0, RLE = 1 };

    struct Stats {
        size_t budgetBytes = 0;
        size_t storedBytes = 0;
        size_t logicalBytes = 0;
        size_t tensorCount = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
        uint64_t bytesDecoded = 0;
        uint64_t evictions = 0;
        size_t chunkCount = 0;
    };

    explicit TensorResidencyCache(size_t budgetBytes = 512ull * 1024ull * 1024ull,
                                  size_t chunkBytes = 64ull * 1024ull)
        : budgetBytes_(budgetBytes), chunkBytes_(chunkBytes) {
        if (!chunkBytes_) throw std::invalid_argument("zero residency chunk size");
    }

    TensorResidencyCache(const TensorResidencyCache&) = delete;
    TensorResidencyCache& operator=(const TensorResidencyCache&) = delete;

    // Register an immutable byte span. No source pointer is retained.
    // Returns false if encoding does not save space or the entry cannot fit.
    bool Register(const std::string& key, const void* source, size_t bytes,
                  bool requireCompression = true) {
        if (key.empty() || (bytes && !source)) return false;
        if (!bytes) return false;

        auto candidate = std::make_shared<Entry>();
        candidate->logicalBytes = bytes;
        const auto* src = static_cast<const uint8_t*>(source);
        size_t total = 0;
        for (size_t offset = 0; offset < bytes;) {
            const size_t n = std::min(chunkBytes_, bytes - offset);
            Chunk chunk;
            chunk.logicalBytes = n;
            EncodeChunk(src + offset, n, chunk);
            if (chunk.payload.size() > std::numeric_limits<size_t>::max() - total)
                return false;
            total += chunk.payload.size();
            candidate->chunks.emplace_back(std::move(chunk));
            offset += n;
        }
        if (requireCompression && total >= bytes) return false;
        candidate->storedBytes = total;

        std::lock_guard<std::mutex> lock(mutex_);
        auto existing = entries_.find(key);
        if (existing != entries_.end()) {
            TouchLocked(*existing->second);
            return true;
        }
        if (total > budgetBytes_) return false;
        EvictLocked(total);
        if (total > budgetBytes_ - storedBytes_) return false;
        candidate->lastUse = ++tick_;
        storedBytes_ += total;
        logicalBytes_ += bytes;
        chunkCount_ += candidate->chunks.size();
        entries_.emplace(key, std::move(candidate));
        return true;
    }

    // Store FP32 values as IEEE-754 binary16. This is a precision-reduction
    // path (not lossless compression); callers must explicitly choose it.
    // The source is copied and converted before admission, so no mmap pointer
    // is retained. Range reads convert only requested values back to FP32.
    bool RegisterF16(const std::string& key, const uint16_t* source,
                     size_t elementCount) {
        if (!source || !elementCount ||
            elementCount > std::numeric_limits<size_t>::max() / sizeof(uint16_t))
            return false;
        return Register(key, source, elementCount * sizeof(uint16_t), false);
    }

    bool RegisterF32AsF16(const std::string& key, const float* source,
                          size_t elementCount) {
        if (!source || !elementCount ||
            elementCount > std::numeric_limits<size_t>::max() / sizeof(uint16_t))
            return false;
        try {
            std::vector<uint16_t> half(elementCount);
            for (size_t i = 0; i < elementCount; ++i)
                half[i] = FloatToHalf(source[i]);
            return RegisterF16(key, half.data(), half.size());
        } catch (...) {
            return false;
        }
    }

    // Exact half-bit range for consumers such as GPU staging/upload paths.
    // No FP32 expansion or full-tensor materialization is performed.
    bool ReadF16Range(const std::string& key, size_t elementOffset,
                      size_t elementCount, uint16_t* destination) {
        if (elementOffset > std::numeric_limits<size_t>::max() / sizeof(uint16_t) ||
            elementCount > std::numeric_limits<size_t>::max() / sizeof(uint16_t) ||
            elementOffset > std::numeric_limits<size_t>::max() - elementCount ||
            (elementCount && !destination))
            return false;
        return ReadRange(key, elementOffset * sizeof(uint16_t),
                         elementCount * sizeof(uint16_t), destination);
    }

    bool ReadF32Range(const std::string& key, size_t elementOffset,
                      size_t elementCount, float* destination) {
        if (elementCount && !destination) return false;
        std::vector<uint16_t> half;
        try { half.resize(elementCount); } catch (...) { return false; }
        if (!ReadF16Range(key, elementOffset, elementCount, half.data()))
            return false;
        for (size_t i = 0; i < elementCount; ++i)
            destination[i] = HalfToFloat(half[i]);
        return true;
    }

    // Read a bounded range into caller-owned memory. On invalid arguments the
    // destination is not touched. Chunks are independently decoded.
    bool ReadRange(const std::string& key, size_t offset, size_t bytes,
                   void* destination) {
        std::shared_ptr<const Entry> entry;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = entries_.find(key);
            if (it == entries_.end()) { ++cacheMisses_; return false; }
            if (offset > it->second->logicalBytes ||
                bytes > it->second->logicalBytes - offset ||
                (bytes && !destination)) return false;
            TouchLocked(*it->second);
            ++cacheHits_;
            entry = it->second;
        }
        if (!bytes) return true;

        auto* out = static_cast<uint8_t*>(destination);
        const size_t firstChunk = offset / chunkBytes_;
        const size_t lastChunk = (offset + bytes - 1) / chunkBytes_;
        size_t written = 0;
        try {
            for (size_t index = firstChunk; index <= lastChunk; ++index) {
                const Chunk& chunk = entry->chunks.at(index);
                std::vector<uint8_t> decoded;
                DecodeChunk(chunk, decoded);
                const size_t chunkStart = index * chunkBytes_;
                const size_t begin = std::max(offset, chunkStart) - chunkStart;
                const size_t end = std::min(offset + bytes,
                    chunkStart + chunk.logicalBytes) - chunkStart;
                const size_t count = end - begin;
                std::memcpy(out + written, decoded.data() + begin, count);
                written += count;
            }
        } catch (...) {
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            bytesDecoded_ = bytes > std::numeric_limits<uint64_t>::max() - bytesDecoded_
                ? std::numeric_limits<uint64_t>::max()
                : bytesDecoded_ + static_cast<uint64_t>(bytes);
        }
        return written == bytes;
    }

    bool Contains(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_.find(key) != entries_.end();
    }

    bool Erase(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = entries_.find(key);
        if (it == entries_.end()) return false;
        storedBytes_ -= it->second->storedBytes;
        logicalBytes_ -= it->second->logicalBytes;
        chunkCount_ -= it->second->chunks.size();
        entries_.erase(it);
        return true;
    }

    void SetBudget(size_t bytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        budgetBytes_ = bytes;
        EvictLocked(0);
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        entries_.clear();
        storedBytes_ = logicalBytes_ = chunkCount_ = 0;
    }

    Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex_);
        Stats s;
        s.budgetBytes = budgetBytes_;
        s.storedBytes = storedBytes_;
        s.logicalBytes = logicalBytes_;
        s.tensorCount = entries_.size();
        s.cacheHits = cacheHits_;
        s.cacheMisses = cacheMisses_;
        s.bytesDecoded = bytesDecoded_;
        s.evictions = evictions_;
        s.chunkCount = chunkCount_;
        return s;
    }

private:
    struct Chunk {
        Encoding encoding = Encoding::Raw;
        size_t logicalBytes = 0;
        std::vector<uint8_t> payload;
    };
    struct Entry {
        std::vector<Chunk> chunks;
        size_t logicalBytes = 0;
        size_t storedBytes = 0;
        uint64_t lastUse = 0;
    };

    static uint16_t FloatToHalf(float value) noexcept {
        uint32_t bits = 0;
        std::memcpy(&bits, &value, sizeof(bits));
        const uint32_t sign = (bits >> 16) & 0x8000u;
        const uint32_t exponent = (bits >> 23) & 0xffu;
        uint32_t mantissa = bits & 0x7fffffu;
        if (exponent == 0xffu) {
            if (!mantissa) return static_cast<uint16_t>(sign | 0x7c00u);
            uint16_t payload = static_cast<uint16_t>(mantissa >> 13);
            if (!payload) payload = 1;
            return static_cast<uint16_t>(sign | 0x7c00u | payload | 0x0200u);
        }
        int32_t halfExp = static_cast<int32_t>(exponent) - 127 + 15;
        if (halfExp >= 31) return static_cast<uint16_t>(sign | 0x7c00u);
        if (halfExp <= 0) {
            if (halfExp < -10) return static_cast<uint16_t>(sign);
            mantissa |= 0x800000u;
            const uint32_t shift = static_cast<uint32_t>(14 - halfExp);
            uint32_t rounded = mantissa >> shift;
            const uint32_t remainder = mantissa & ((1u << shift) - 1u);
            const uint32_t halfway = 1u << (shift - 1u);
            if (remainder > halfway || (remainder == halfway && (rounded & 1u)))
                ++rounded;
            return static_cast<uint16_t>(sign | rounded);
        }
        uint32_t rounded = mantissa >> 13;
        const uint32_t remainder = mantissa & 0x1fffu;
        if (remainder > 0x1000u || (remainder == 0x1000u && (rounded & 1u))) {
            ++rounded;
            if (rounded == 0x400u) {
                rounded = 0;
                ++halfExp;
                if (halfExp >= 31) return static_cast<uint16_t>(sign | 0x7c00u);
            }
        }
        return static_cast<uint16_t>(sign |
            (static_cast<uint32_t>(halfExp) << 10) | rounded);
    }

    static float HalfToFloat(uint16_t value) noexcept {
        const uint32_t sign = static_cast<uint32_t>(value & 0x8000u) << 16;
        uint32_t exponent = (value >> 10) & 0x1fu;
        uint32_t mantissa = value & 0x03ffu;
        uint32_t bits = 0;
        if (exponent == 0) {
            if (!mantissa) bits = sign;
            else {
                int32_t e = -14;
                while ((mantissa & 0x0400u) == 0) { mantissa <<= 1; --e; }
                mantissa &= 0x03ffu;
                bits = sign | (static_cast<uint32_t>(e + 127) << 23) |
                       (mantissa << 13);
            }
        } else if (exponent == 0x1fu) {
            bits = sign | 0x7f800000u | (mantissa << 13);
        } else {
            bits = sign | ((exponent - 15u + 127u) << 23) | (mantissa << 13);
        }
        float result = 0.0f;
        std::memcpy(&result, &bits, sizeof(result));
        return result;
    }

    static void EncodeChunk(const uint8_t* src, size_t bytes, Chunk& out) {
        std::vector<uint8_t> rle;
        rle.reserve(bytes);
        for (size_t i = 0; i < bytes;) {
            size_t run = 1;
            while (run < 255 && run < bytes - i && src[i + run] == src[i]) ++run;
            rle.push_back(static_cast<uint8_t>(run));
            rle.push_back(src[i]);
            i += run;
            if (rle.size() >= bytes) break;
        }
        if (rle.size() < bytes) {
            out.encoding = Encoding::RLE;
            out.payload = std::move(rle);
        } else {
            out.encoding = Encoding::Raw;
            out.payload.assign(src, src + bytes);
        }
    }

    static void DecodeChunk(const Chunk& chunk, std::vector<uint8_t>& out) {
        out.resize(chunk.logicalBytes);
        if (chunk.encoding == Encoding::Raw) {
            if (chunk.payload.size() != chunk.logicalBytes)
                throw std::runtime_error("raw residency chunk size mismatch");
            if (!out.empty()) std::memcpy(out.data(), chunk.payload.data(), out.size());
            return;
        }
        if (chunk.encoding != Encoding::RLE || (chunk.payload.size() & 1u))
            throw std::runtime_error("invalid residency chunk encoding");
        size_t total = 0;
        for (size_t i = 0; i < chunk.payload.size(); i += 2) {
            const size_t run = chunk.payload[i];
            if (!run || run > chunk.logicalBytes - total)
                throw std::runtime_error("invalid residency RLE run");
            total += run;
        }
        if (total != chunk.logicalBytes)
            throw std::runtime_error("residency RLE length mismatch");
        size_t at = 0;
        for (size_t i = 0; i < chunk.payload.size(); i += 2) {
            const size_t run = chunk.payload[i];
            std::memset(out.data() + at, chunk.payload[i + 1], run);
            at += run;
        }
    }

    void TouchLocked(Entry& entry) const { entry.lastUse = ++tick_; }

    void EvictLocked(size_t incoming) {
        while (storedBytes_ > budgetBytes_ ||
               incoming > budgetBytes_ - storedBytes_) {
            auto victim = entries_.end();
            for (auto it = entries_.begin(); it != entries_.end(); ++it)
                if (victim == entries_.end() ||
                    it->second->lastUse < victim->second->lastUse) victim = it;
            if (victim == entries_.end()) break;
            storedBytes_ -= victim->second->storedBytes;
            logicalBytes_ -= victim->second->logicalBytes;
            chunkCount_ -= victim->second->chunks.size();
            entries_.erase(victim);
            ++evictions_;
        }
    }

    mutable std::mutex mutex_;
    mutable uint64_t tick_ = 0;
    size_t budgetBytes_ = 0;
    size_t chunkBytes_ = 0;
    size_t storedBytes_ = 0;
    size_t logicalBytes_ = 0;
    size_t chunkCount_ = 0;
    uint64_t cacheHits_ = 0;
    uint64_t cacheMisses_ = 0;
    uint64_t bytesDecoded_ = 0;
    uint64_t evictions_ = 0;
    std::unordered_map<std::string, std::shared_ptr<Entry>> entries_;
};

} // namespace Deep2

namespace gguf_shard_cache {
using TensorResidencyCache = Deep2::TensorResidencyCache;
} // namespace gguf_shard_cache
