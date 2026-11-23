#pragma once
// Immutable in-memory compressed tensor, built by streaming GGUF bytes.
// No full uncompressed tensor is retained after construction.
#include "native_file_tensor_reader.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

namespace rawrxd::compression {
class ResidentCompressedTensor {
public:
    explicit ResidentCompressedTensor(std::size_t blockBytes = 64 * 1024)
        : blockBytes_(blockBytes) {
        if (!blockBytes_) throw std::invalid_argument("zero block size");
    }
    void load(FileTensorReader& source) {
        std::vector<Block> next;
        const auto length = source.size();
        if (length > std::numeric_limits<std::size_t>::max())
            throw std::length_error("tensor exceeds address space");
        if (length) next.reserve(1 + (static_cast<std::size_t>(length) - 1) / blockBytes_);
        source.for_each_compressed_block(blockBytes_, [&](std::uint64_t offset, const Block& b) {
            if (offset / blockBytes_ != next.size())
                throw std::runtime_error("nonsequential compressed blocks");
            next.push_back(b);
        });
        blocks_.swap(next);
        size_ = static_cast<std::size_t>(length);
    }
    std::size_t size() const noexcept { return size_; }
    std::size_t block_count() const noexcept { return blocks_.size(); }
    std::size_t compressed_bytes() const noexcept {
        std::size_t result = 0;
        for (const auto& b : blocks_) result += b.payload.size();
        return result;
    }
    void read(std::size_t offset, std::uint8_t* out, std::size_t bytes) const {
        if (offset > size_ || bytes > size_ - offset || (bytes && !out))
            throw std::out_of_range("invalid compressed tensor read");
        while (bytes) {
            const auto index = offset / blockBytes_;
            const auto within = offset % blockBytes_;
            const auto& block = blocks_.at(index);
            const auto decoded = decode(block);
            const auto n = std::min(bytes, decoded.size() - within);
            std::copy_n(decoded.data() + within, n, out);
            offset += n; out += n; bytes -= n;
        }
    }
private:
    std::size_t blockBytes_;
    std::size_t size_ = 0;
    std::vector<Block> blocks_;
};
} // namespace rawrxd::compression
