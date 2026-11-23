#pragma once
#include "codec/compression_core.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>
#include <vector>

namespace rawrxd::compression {

// Independent zlib blocks retained in compressed form. Each read inflates only
// the blocks overlapping the requested byte range, never the whole tensor.
class ChunkedResidentBytes {
public:
    struct Block {
        std::vector<std::uint8_t> encoded;
        std::size_t decodedSize = 0;
    };
    Status assign(const std::uint8_t* src, std::size_t size,
                  std::size_t blockBytes = 65536) {
        if ((!src && size) || blockBytes == 0 || blockBytes > MaxOneShotBytes)
            return Status::InvalidInput;
        std::vector<Block> pending;
        try {
        for (std::size_t off = 0; off < size;) {
            const auto n = std::min(blockBytes, size - off);
            auto result = compress(src + off, n);
            if (!result) return result.status;
            pending.push_back({std::move(result.bytes), n});
            off += n;
        }
        } catch (const std::bad_alloc&) {
            return Status::AllocationFailure;
        } catch (const std::length_error&) {
            return Status::AllocationFailure;
        }
        blocks_ = std::move(pending);
        total_ = size;
        blockBytes_ = blockBytes;
        return Status::Ok;
    }
    Status read(std::size_t offset, std::uint8_t* dst, std::size_t count) const {
        if (offset > total_ || count > total_ - offset || (!dst && count))
            return Status::InvalidInput;
        if (!count) return Status::Ok;
        const std::size_t last = offset + count;
        std::size_t pos = offset;
        while (pos < last) {
            const std::size_t index = pos / blockBytes_;
            const auto& block = blocks_[index];
            auto decoded = decompress(block.encoded.data(), block.encoded.size(),
                                      block.decodedSize);
            if (!decoded) return decoded.status;
            if (decoded.bytes.size() != block.decodedSize)
                return Status::CorruptData;
            const std::size_t local = pos % blockBytes_;
            const std::size_t n = std::min(last - pos, block.decodedSize - local);
            std::copy_n(decoded.bytes.data() + local, n, dst + (pos - offset));
            pos += n;
        }
        return Status::Ok;
    }
    std::size_t decodedSize() const noexcept { return total_; }
    std::size_t compressedBytes() const noexcept {
        std::size_t sum = 0;
        for (const auto& b : blocks_) sum += b.encoded.size();
        return sum;
    }
    std::size_t peakDecodeBlockBytes() const noexcept { return blockBytes_; }
    std::size_t blockCount() const noexcept { return blocks_.size(); }
private:
    std::vector<Block> blocks_;
    std::size_t total_ = 0;
    std::size_t blockBytes_ = 65536;
};
} // namespace rawrxd::compression
