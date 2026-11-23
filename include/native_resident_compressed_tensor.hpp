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
        for (const auto& b : blocks_) {
            if (b.payload.size() > std::numeric_limits<std::size_t>::max() - result)
                return std::numeric_limits<std::size_t>::max();
            result += b.payload.size();
        }
        return result;
    }
    // Account for retained vector capacity and per-block metadata as well as
    // payload bytes. Use this value for residency admission/budgeting; the
    // compressed_bytes() value is only the wire-payload ratio.
    std::size_t resident_bytes() const noexcept {
        if (blocks_.capacity() >
            std::numeric_limits<std::size_t>::max() / sizeof(Block))
            return std::numeric_limits<std::size_t>::max();
        std::size_t total = blocks_.capacity() * sizeof(Block);
        for (const auto& b : blocks_) {
            if (b.payload.capacity() >
                std::numeric_limits<std::size_t>::max() - total)
                return std::numeric_limits<std::size_t>::max();
            total += b.payload.capacity();
        }
        return total;
    }
    void read(std::size_t offset, std::uint8_t* out, std::size_t bytes) const {
        if (offset > size_ || bytes > size_ - offset || (bytes && !out))
            throw std::out_of_range("invalid compressed tensor read");
        while (bytes) {
            const auto index = offset / blockBytes_;
            const auto within = offset % blockBytes_;
            const auto& block = blocks_.at(index);
            if (within >= block.decoded_size)
                throw std::runtime_error("invalid resident block offset");
            const auto n = std::min(bytes, block.decoded_size - within);
            if (block.lz4) {
                // LZ4-style matches need prior output context; expand only this
                // bounded storage block, never the full tensor.
                const auto decoded = decode(block);
                std::copy_n(decoded.data() + within, n, out);
            } else if (!block.rle) {
                if (block.payload.size() != block.decoded_size)
                    throw std::runtime_error("invalid resident raw block");
                std::copy_n(block.payload.data() + within, n, out);
            } else {
                // RLE can satisfy a subrange without a full-block scratch copy.
                if (block.payload.size() % 2)
                    throw std::runtime_error("invalid resident RLE block");
                std::size_t cursor = 0, copied = 0;
                for (std::size_t i = 0; i < block.payload.size(); i += 2) {
                    const auto run = static_cast<std::size_t>(block.payload[i]);
                    if (!run || cursor > block.decoded_size ||
                        run > block.decoded_size - cursor)
                        throw std::runtime_error("invalid resident RLE run");
                    const auto begin = std::max(cursor, within);
                    const auto finish = std::min(cursor + run, within + n);
                    if (finish > begin) {
                        std::fill_n(out + (begin - within), finish - begin,
                                    block.payload[i + 1]);
                        copied += finish - begin;
                    }
                    cursor += run;
                }
                if (cursor != block.decoded_size || copied != n)
                    throw std::runtime_error("truncated resident RLE block");
            }
            offset += n; out += n; bytes -= n;
        }
    }
private:
    std::size_t blockBytes_;
    std::size_t size_ = 0;
    std::vector<Block> blocks_;
};
} // namespace rawrxd::compression
