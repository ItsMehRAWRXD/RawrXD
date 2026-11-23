#pragma once
// Immutable compressed tensor blocks with exact byte-range reads.
// Storage is bounded by the source tensor size: incompressible blocks remain raw.
#include "native_compressed_residency.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>

namespace rawrxd::compression {
class CompressedTensor {
public:
    explicit CompressedTensor(std::size_t block_bytes = 64 * 1024)
        : block_bytes_(block_bytes) {
        if (!block_bytes_) throw std::invalid_argument("zero block size");
    }
    void assign(const std::uint8_t* source, std::size_t bytes) {
        if (bytes && !source) throw std::invalid_argument("null tensor");
        std::vector<Block> next;
        if (bytes) next.reserve(1 + (bytes - 1) / block_bytes_);
        for (std::size_t offset = 0; offset < bytes;) {
            const std::size_t count = std::min(block_bytes_, bytes - offset);
            next.push_back(encode(source + offset, count));
            offset += count;
        }
        blocks_.swap(next);
        size_ = bytes;
    }
    std::size_t size() const noexcept { return size_; }
    std::size_t block_count() const noexcept { return blocks_.size(); }
    std::size_t stored_bytes() const noexcept {
        std::size_t total = 0;
        for (const auto& b : blocks_) total += b.payload.size();
        return total;
    }
    // Range validation is performed before any destination writes.
    void read(std::size_t offset, std::uint8_t* destination, std::size_t bytes) const {
        if (offset > size_ || bytes > size_ - offset || (bytes && !destination))
            throw std::out_of_range("invalid tensor range");
        std::size_t written = 0;
        while (written < bytes) {
            const std::size_t block_index = offset / block_bytes_;
            const std::size_t within = offset % block_bytes_;
            const auto decoded = decode(blocks_.at(block_index));
            const std::size_t n = std::min(bytes - written, decoded.size() - within);
            std::memcpy(destination + written, decoded.data() + within, n);
            written += n;
            offset += n;
        }
    }
    // Callers may decode a single block directly for quantized kernel dispatch.
    const Block& block(std::size_t index) const { return blocks_.at(index); }
private:
    std::size_t block_bytes_;
    std::size_t size_ = 0;
    std::vector<Block> blocks_;
};
} // namespace rawrxd::compression
