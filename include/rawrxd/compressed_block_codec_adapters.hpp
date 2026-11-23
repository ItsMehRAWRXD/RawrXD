#pragma once
#include "rawrxd/compressed_block_store.hpp"
#include "rawrxd/native_lz_block_codec.hpp"
#include "codec/compression_core.h"

#include <algorithm>
#include <limits>
#include <utility>

namespace rawrxd::compression {

inline BlockDecoder nativeLzBlockDecoder() {
    return [](const std::uint8_t* src, std::size_t srcSize,
              std::uint8_t* dst, std::size_t dstSize) {
        return native_lz::decode(src, srcSize, dst, dstSize);
    };
}

inline BlockDecoder zlibBlockDecoder() {
    return [](const std::uint8_t* src, std::size_t srcSize,
              std::uint8_t* dst, std::size_t dstSize) {
        if ((!src && srcSize) || (!dst && dstSize)) return false;
        // Block builders store incompressible data verbatim. A zlib stream is
        // only retained when it is strictly smaller than the raw block.
        if (srcSize == dstSize) {
            if (dstSize) std::copy_n(src, dstSize, dst);
            return true;
        }
        const auto result = rawrxd::compression::decompress(src, srcSize, dstSize);
        if (!result || result.bytes.size() != dstSize) return false;
        if (dstSize) std::copy(result.bytes.begin(), result.bytes.end(), dst);
        return true;
    };
}

using BlockEncoder = std::function<bool(const std::uint8_t*, std::size_t,
                                        std::vector<std::uint8_t>&)>;

inline BlockEncoder nativeLzBlockEncoder() {
    return [](const std::uint8_t* src, std::size_t size,
              std::vector<std::uint8_t>& out) {
        return native_lz::encode(src, size, out);
    };
}

inline BlockEncoder zlibBlockEncoder(int level = -1) {
    return [level](const std::uint8_t* src, std::size_t size,
                   std::vector<std::uint8_t>& out) {
        const auto result = rawrxd::compression::compress(src, size, level);
        if (!result) return false;
        out = result.bytes;
        // The paired decoder recognizes raw fallback by exact-size blocks.
        if (out.size() >= size) {
            out.assign(src, src + size);
        }
        return true;
    };
}

// Build a contiguous encoded stream plus a complete logical block directory.
// The original tensor is never copied into one monolithic intermediate buffer.
inline bool encodeBlockStream(const std::uint8_t* raw, std::size_t rawSize,
                              std::size_t blockBytes, const BlockEncoder& encoder,
                              std::vector<std::uint8_t>& encoded,
                              std::vector<CompressedBlock>& directory) {
    encoded.clear();
    directory.clear();
    if ((!raw && rawSize) || !blockBytes || !encoder) return false;
    if (rawSize == 0) return true;
    const std::size_t blockCount = 1 + (rawSize - 1) / blockBytes;
    if (blockCount > directory.max_size()) return false;
    try {
        directory.reserve(blockCount);
        for (std::size_t offset = 0; offset < rawSize;) {
            const std::size_t count = std::min(blockBytes, rawSize - offset);
            std::vector<std::uint8_t> payload;
            if (!encoder(raw + offset, count, payload) || payload.empty()) {
                encoded.clear(); directory.clear(); return false;
            }
            // Compression is optional per block; never retain a larger payload.
            if (payload.size() >= count)
                payload.assign(raw + offset, raw + offset + count);
            if (encoded.size() > encoded.max_size() - payload.size()) {
                encoded.clear(); directory.clear(); return false;
            }
            CompressedBlock block;
            block.logical_offset = offset;
            block.raw_size = count;
            block.compressed_offset = encoded.size();
            block.compressed_size = payload.size();
            block.raw_crc32 = crc32_bytes(raw + offset, count);
            encoded.insert(encoded.end(), payload.begin(), payload.end());
            directory.push_back(block);
            offset += count;
        }
        return true;
    } catch (...) {
        encoded.clear(); directory.clear(); return false;
    }
}

inline std::unique_ptr<CompressedBlockStore> makeNativeLzBlockStore(
    const std::uint8_t* raw, std::size_t rawSize, std::size_t blockBytes,
    std::size_t decodedCacheBudget) {
    std::vector<std::uint8_t> encoded;
    std::vector<CompressedBlock> directory;
    if (!encodeBlockStream(raw, rawSize, blockBytes, nativeLzBlockEncoder(),
                           encoded, directory)) return {};
    try {
        return std::make_unique<CompressedBlockStore>(
            std::move(encoded), std::move(directory), rawSize,
            decodedCacheBudget, nativeLzBlockDecoder());
    } catch (...) { return {}; }
}

inline std::unique_ptr<CompressedBlockStore> makeZlibBlockStore(
    const std::uint8_t* raw, std::size_t rawSize, std::size_t blockBytes,
    std::size_t decodedCacheBudget, int level = -1) {
    std::vector<std::uint8_t> encoded;
    std::vector<CompressedBlock> directory;
    if (!encodeBlockStream(raw, rawSize, blockBytes, zlibBlockEncoder(level),
                           encoded, directory)) return {};
    try {
        return std::make_unique<CompressedBlockStore>(
            std::move(encoded), std::move(directory), rawSize,
            decodedCacheBudget, zlibBlockDecoder());
    } catch (...) { return {}; }
}

} // namespace rawrxd::compression
