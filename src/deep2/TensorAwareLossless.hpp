#pragma once
// Adaptive, byte-exact block compression for model-weight tensors.
// Standalone C++17 + existing zlib dependency. Wire into runtime separately.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <vector>
#include <zlib.h>

namespace rawrxd::weights {
enum class BlockCodec : uint8_t { Raw = 0, Zlib = 1, ByteShuffleZlib = 2, DeltaShuffleZlib = 3 };
struct Block {
    BlockCodec codec = BlockCodec::Raw;
    uint32_t plain_size = 0;
    uint32_t crc32_plain = 0;
    std::vector<uint8_t> payload;
};
struct Tensor {
    uint64_t plain_size = 0;
    uint32_t block_size = 0;
    uint8_t element_bytes = 1;
    std::vector<Block> blocks;
};
inline std::vector<uint8_t> shuffle(const uint8_t* p, size_t n, size_t stride) {
    std::vector<uint8_t> out(n);
    const size_t count = n / stride;
    for (size_t lane = 0; lane < stride; ++lane)
        for (size_t i = 0; i < count; ++i)
            out[lane * count + i] = p[i * stride + lane];
    std::copy(p + count * stride, p + n, out.begin() + count * stride);
    return out;
}
inline std::vector<uint8_t> unshuffle(const uint8_t* p, size_t n, size_t stride) {
    std::vector<uint8_t> out(n);
    const size_t count = n / stride;
    for (size_t lane = 0; lane < stride; ++lane)
        for (size_t i = 0; i < count; ++i)
            out[i * stride + lane] = p[lane * count + i];
    std::copy(p + count * stride, p + n, out.begin() + count * stride);
    return out;
}
// Reversible per-lane byte delta coding. Useful for correlated floating-point
// exponent/sign bytes and structured quantization metadata; never lossy.
inline std::vector<uint8_t> delta_lanes(const uint8_t* p, size_t n, size_t stride) {
    std::vector<uint8_t> out(n);
    for (size_t lane=0; lane<stride; ++lane) {
        uint8_t prev=0;
        for (size_t i=lane; i<n; i+=stride) {
            const uint8_t cur=p[i];
            out[i]=static_cast<uint8_t>(cur-prev);
            prev=cur;
        }
    }
    return out;
}
inline std::vector<uint8_t> undelta_lanes(const uint8_t* p, size_t n, size_t stride) {
    std::vector<uint8_t> out(n);
    for (size_t lane=0; lane<stride; ++lane) {
        uint8_t prev=0;
        for (size_t i=lane; i<n; i+=stride) {
            prev=static_cast<uint8_t>(prev+p[i]);
            out[i]=prev;
        }
    }
    return out;
}
inline uint32_t checksum(const uint8_t* p, size_t n) {
    uLong c = crc32(0L, Z_NULL, 0);
    while (n) {
        const uInt step = static_cast<uInt>(std::min<size_t>(n, 1u << 20));
        c = crc32(c, p, step);
        p += step; n -= step;
    }
    return static_cast<uint32_t>(c);
}
inline std::vector<uint8_t> zcompress(const uint8_t* p, size_t n) {
    if (n > static_cast<size_t>(std::numeric_limits<uLong>::max()))
        throw std::length_error("zlib input too large");
    uLongf cap = compressBound(static_cast<uLong>(n));
    std::vector<uint8_t> out(static_cast<size_t>(cap));
    if (compress2(out.data(), &cap, p, static_cast<uLong>(n), Z_BEST_SPEED) != Z_OK)
        throw std::runtime_error("zlib compression failed");
    out.resize(static_cast<size_t>(cap));
    return out;
}
inline Tensor encode(const uint8_t* data, size_t size,
                     uint8_t element_bytes = 1, uint32_t block_size = 65536) {
    if ((!data && size) || (element_bytes != 1 && element_bytes != 2 &&
                            element_bytes != 4 && element_bytes != 8) || !block_size)
        throw std::invalid_argument("invalid tensor compression arguments");
    Tensor t;
    t.plain_size = size; t.block_size = block_size; t.element_bytes = element_bytes;
    for (size_t offset = 0; offset < size;) {
        const size_t n = std::min<size_t>(block_size, size - offset);
        const uint8_t* p = data + offset;
        Block b;
        b.plain_size = static_cast<uint32_t>(n);
        b.crc32_plain = checksum(p, n);
        b.payload.assign(p, p + n);
        auto compressed = zcompress(p, n);
        if (compressed.size() < b.payload.size()) {
            b.codec = BlockCodec::Zlib;
            b.payload = std::move(compressed);
        }
        if (element_bytes > 1) {
            auto delta = delta_lanes(p, n, element_bytes);
            auto delta_shuffled = shuffle(delta.data(), delta.size(), element_bytes);
            compressed = zcompress(delta_shuffled.data(), delta_shuffled.size());
            if (compressed.size() < b.payload.size()) {
                b.codec = BlockCodec::DeltaShuffleZlib;
                b.payload = std::move(compressed);
            }
            auto transposed = shuffle(p, n, element_bytes);
            compressed = zcompress(transposed.data(), transposed.size());
            if (compressed.size() < b.payload.size()) {
                b.codec = BlockCodec::ByteShuffleZlib;
                b.payload = std::move(compressed);
            }
        }
        t.blocks.push_back(std::move(b));
        offset += n;
    }
    return t;
}
inline std::vector<uint8_t> decode_block(const Tensor& t, size_t index) {
    if (index >= t.blocks.size() || !t.block_size ||
        (t.element_bytes != 1 && t.element_bytes != 2 &&
         t.element_bytes != 4 && t.element_bytes != 8))
        throw std::invalid_argument("invalid block metadata");
    const Block& b = t.blocks[index];
    if (!b.plain_size || b.plain_size > t.block_size)
        throw std::runtime_error("invalid block size");
    std::vector<uint8_t> out(b.plain_size);
    if (b.codec == BlockCodec::Raw) {
        if (b.payload.size() != b.plain_size)
            throw std::runtime_error("raw block size mismatch");
        out = b.payload;
    } else if (b.codec == BlockCodec::Zlib || b.codec == BlockCodec::ByteShuffleZlib || b.codec == BlockCodec::DeltaShuffleZlib) {
        uLongf decoded = b.plain_size;
        if (uncompress(out.data(), &decoded, b.payload.data(),
                       static_cast<uLong>(b.payload.size())) != Z_OK ||
            decoded != b.plain_size)
            throw std::runtime_error("compressed block invalid");
        if (b.codec == BlockCodec::ByteShuffleZlib || b.codec == BlockCodec::DeltaShuffleZlib)
            out = unshuffle(out.data(), out.size(), t.element_bytes);
        if (b.codec == BlockCodec::DeltaShuffleZlib)
            out = undelta_lanes(out.data(), out.size(), t.element_bytes);
    } else {
        throw std::runtime_error("unknown codec");
    }
    if (checksum(out.data(), out.size()) != b.crc32_plain)
        throw std::runtime_error("block checksum mismatch");
    return out;
}
inline std::vector<uint8_t> decode_range(const Tensor& t, uint64_t offset, size_t length) {
    if (!t.block_size || offset > t.plain_size ||
        length > t.plain_size - offset)
        throw std::out_of_range("tensor range out of bounds");
    std::vector<uint8_t> result(length);
    size_t copied = 0;
    while (copied < length) {
        const uint64_t position = offset + copied;
        const size_t index = static_cast<size_t>(position / t.block_size);
        auto block = decode_block(t, index);
        const size_t within = static_cast<size_t>(position % t.block_size);
        if (within >= block.size()) throw std::runtime_error("inconsistent block index");
        const size_t take = std::min(length - copied, block.size() - within);
        std::memcpy(result.data() + copied, block.data() + within, take);
        copied += take;
    }
    return result;
}
} // namespace rawrxd::weights
