#pragma once
// Portable little-endian on-disk format for TensorAwareLossless blocks.
// Independent of struct padding, pointers, Qt, and host ABI.
#include "TensorAwareLossless.hpp"
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>
namespace rawrxd::weights {
namespace detail {
inline void put32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i=0;i<4;++i) out.push_back(static_cast<uint8_t>(v >> (8*i)));
}
inline void put64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i=0;i<8;++i) out.push_back(static_cast<uint8_t>(v >> (8*i)));
}
struct Reader {
    const std::vector<uint8_t>& bytes;
    size_t pos=0;
    uint32_t u32() {
        if (bytes.size()-pos < 4) throw std::runtime_error("truncated tensor header");
        uint32_t v=0;
        for (int i=0;i<4;++i) v |= uint32_t(bytes[pos++]) << (8*i);
        return v;
    }
    uint64_t u64() {
        uint64_t lo=u32(), hi=u32();
        return lo | (hi << 32);
    }
};
}
inline std::vector<uint8_t> serialize(const Tensor& t) {
    if (!t.block_size || (t.element_bytes != 1 && t.element_bytes != 2 &&
        t.element_bytes != 4 && t.element_bytes != 8) ||
        t.blocks.size() > std::numeric_limits<uint32_t>::max())
        throw std::invalid_argument("invalid tensor metadata");
    std::vector<uint8_t> out;
    detail::put32(out, 0x31545752u); // RWT1
    detail::put32(out, 1);
    detail::put64(out, t.plain_size);
    detail::put32(out, t.block_size);
    detail::put32(out, t.element_bytes);
    detail::put32(out, static_cast<uint32_t>(t.blocks.size()));
    uint64_t sum=0;
    for (size_t i=0;i<t.blocks.size();++i) {
        const auto& b=t.blocks[i];
        if (sum >= t.plain_size) throw std::invalid_argument("excess tensor blocks");
        const uint64_t remaining=t.plain_size-sum;
        const uint32_t expected=static_cast<uint32_t>(
            std::min<uint64_t>(t.block_size,remaining));
        if (!expected || b.plain_size != expected ||
            b.payload.size() > std::numeric_limits<uint32_t>::max() ||
            static_cast<uint8_t>(b.codec)>3 ||
            (b.codec==BlockCodec::Raw && b.payload.size()!=expected))
            throw std::invalid_argument("invalid block metadata");
        sum+=expected;
        detail::put32(out, static_cast<uint32_t>(b.codec));
        detail::put32(out, b.plain_size);
        detail::put32(out, b.crc32_plain);
        detail::put32(out, static_cast<uint32_t>(b.payload.size()));
        out.insert(out.end(),b.payload.begin(),b.payload.end());
    }
    if (sum!=t.plain_size) throw std::invalid_argument("tensor size mismatch");
    return out;
}
inline Tensor deserialize(const std::vector<uint8_t>& bytes,
                          uint64_t max_plain_bytes = (uint64_t(1)<<40),
                          uint32_t max_block_bytes = (1u<<24)) {
    detail::Reader r{bytes};
    if (r.u32()!=0x31545752u || r.u32()!=1)
        throw std::runtime_error("invalid tensor format");
    Tensor t;
    t.plain_size=r.u64();
    t.block_size=r.u32();
    const uint32_t element=r.u32(), count=r.u32();
    if (!t.block_size || t.block_size>max_block_bytes ||
        (element!=1 && element!=2 && element!=4 && element!=8) ||
        t.plain_size>max_plain_bytes ||
        (t.plain_size/t.block_size + (t.plain_size%t.block_size!=0)) != count)
        throw std::runtime_error("invalid tensor dimensions");
    if (count > (bytes.size()-r.pos)/16)
        throw std::runtime_error("truncated tensor block directory");
    t.element_bytes=static_cast<uint8_t>(element);
    uint64_t sum=0;
    for (uint32_t i=0;i<count;++i) {
        Block b;
        const uint32_t codec=r.u32();
        b.plain_size=r.u32();
        b.crc32_plain=r.u32();
        const uint32_t n=r.u32();
        if (sum >= t.plain_size) throw std::runtime_error("excess tensor blocks");
        const uint32_t expected=static_cast<uint32_t>(
            std::min<uint64_t>(t.block_size,t.plain_size-sum));
        if (codec>3 || b.plain_size!=expected || !expected ||
            n>bytes.size()-r.pos || n>max_block_bytes+65536u ||
            (codec==0 && n!=expected))
            throw std::runtime_error("invalid block encoding");
        b.codec=static_cast<BlockCodec>(codec);
        b.payload.assign(bytes.begin()+r.pos,bytes.begin()+r.pos+n);
        r.pos+=n;
        sum+=expected;
        t.blocks.push_back(std::move(b));
    }
    if (sum!=t.plain_size || r.pos!=bytes.size())
        throw std::runtime_error("tensor length mismatch");
    return t;
}
} // namespace rawrxd::weights
