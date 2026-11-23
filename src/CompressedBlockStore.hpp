#pragma once
// Lossless, block-addressable compressed residency for raw tensor storage.
// This does not dequantize GGUF blocks: callers receive the original encoded bytes.
// Requires zlib (already used by src/codec/compression.cpp).
#include <zlib.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace deep2 {
class CompressedBlockStore {
public:
    struct Block {
        std::vector<std::uint8_t> bytes;
        std::uint32_t originalSize = 0;
        bool compressed = false;
    };

    explicit CompressedBlockStore(std::size_t blockBytes = 65536)
        : blockBytes_(blockBytes) {
        if (blockBytes == 0 || blockBytes > std::numeric_limits<uInt>::max())
            throw std::invalid_argument("invalid block size");
    }

    void assign(const std::uint8_t* source, std::size_t size, int level = Z_DEFAULT_COMPRESSION) {
        if (size && !source) throw std::invalid_argument("null tensor data");
        if (level < Z_DEFAULT_COMPRESSION || level > Z_BEST_COMPRESSION)
            throw std::invalid_argument("invalid compression level");
        std::vector<Block> next;
        if (size / blockBytes_ > next.max_size()) throw std::length_error("too many blocks");
        next.reserve(size / blockBytes_ + (size % blockBytes_ != 0));
        for (std::size_t pos = 0; pos < size;) {
            const auto n = std::min(blockBytes_, size - pos);
            Block b;
            b.originalSize = static_cast<std::uint32_t>(n);
            const uLongf bound = compressBound(static_cast<uLong>(n));
            b.bytes.resize(static_cast<std::size_t>(bound));
            uLongf written = bound;
            const int rc = compress2(b.bytes.data(), &written, source + pos,
                                     static_cast<uLong>(n), level);
            if (rc != Z_OK) throw std::runtime_error("compression failed");
            if (written < n) {
                b.bytes.resize(static_cast<std::size_t>(written));
                b.compressed = true;
            } else {
                b.bytes.assign(source + pos, source + pos + n);
            }
            next.push_back(std::move(b));
            pos += n;
        }
        std::lock_guard<std::mutex> lock(mu_);
        blocks_.swap(next);
        size_ = size;
    }

    // Reads only intersecting blocks. The destination must accommodate 'length' bytes.
    // Concurrent readers are serialized with assign to avoid invalidated block references.
    bool read(std::size_t offset, std::size_t length, std::uint8_t* destination) const {
        std::lock_guard<std::mutex> lock(mu_);
        if (offset > size_ || length > size_ - offset || (length && !destination)) return false;
        if (!length) return true;
        std::vector<std::uint8_t> scratch(blockBytes_);
        std::size_t remaining = length;
        while (remaining) {
            const std::size_t index = offset / blockBytes_;
            const std::size_t within = offset % blockBytes_;
            const Block& b = blocks_[index];
            const auto take = std::min(remaining, static_cast<std::size_t>(b.originalSize) - within);
            if (b.compressed) {
                uLongf decoded = b.originalSize;
                if (uncompress(scratch.data(), &decoded, b.bytes.data(),
                               static_cast<uLong>(b.bytes.size())) != Z_OK ||
                    decoded != b.originalSize) return false;
                std::memcpy(destination, scratch.data() + within, take);
            } else {
                if (b.bytes.size() != b.originalSize) return false;
                std::memcpy(destination, b.bytes.data() + within, take);
            }
            destination += take;
            offset += take;
            remaining -= take;
        }
        return true;
    }

    std::size_t originalBytes() const {
        std::lock_guard<std::mutex> lock(mu_);
        return size_;
    }
    std::size_t residentBytes() const {
        std::lock_guard<std::mutex> lock(mu_);
        std::size_t n = 0;
        for (const auto& b : blocks_) n += b.bytes.size();
        return n; // payload only; excludes vector and allocator overhead
    }
    std::size_t blockCount() const {
        std::lock_guard<std::mutex> lock(mu_);
        return blocks_.size();
    }
private:
    const std::size_t blockBytes_;
    mutable std::mutex mu_;
    std::vector<Block> blocks_;
    std::size_t size_ = 0;
};
} // namespace deep2
