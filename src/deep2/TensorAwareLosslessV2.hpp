#ifndef RAWRXD_TENSORAWARE_LOSSLESS_V2_HPP
#define RAWRXD_TENSORAWARE_LOSSLESS_V2_HPP
// ============================================================================
// TensorAwareLosslessV2.hpp -- REAP-style structural compression for GGUF
// quantized weights. Instead of treating a packed Q2_K/Q4_K block as one opaque
// byte stream (where the high-entropy 2/4/6-bit value field dominates and zlib
// chokes), this reverse-engineers each quantization format's field layout and
// DEINTERLEAVES it into homogeneous streams:
//
//   Q2_K block (84 B): scales[16] | qs[64] | d[2] | dmin[2]
//   Q4_K block (144B): d[2] | dmin[2] | scales[12] | qs[128]
//   ...
//
// Each stream is compressed independently (scales/d/dmin are low-entropy fp16
// and shrink a lot; the qs stream is 2/4/6-bit packed and entropy-codes on its
// own). Reconstruction re-interleaves byte-exact. A whole-tensor raw/zlib path
// is kept as a best-of fallback so incompressible data never expands.
//
// Header-only, C++17, zlib. Link rawrxd_compression_core or -lz.
// ============================================================================
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <zlib.h>

namespace rawrxd::weights::v2 {

// One field inside a quantization block: name + byte length within the block.
struct QField { const char* name; uint32_t bytes; };

// Described quantization block layout. Empty = not a known packed quant type.
struct QLayout {
    uint32_t block_bytes = 0;
    std::vector<QField> fields; // in on-disk order
};

// GGUF type ids (match ggml.h). Returns the field layout for packed types.
inline QLayout GetQLayout(uint32_t type) {
    switch (type) {
        case 2:  return {18,  {{"d",2},{"qs",16}}};                       // Q4_0
        case 3:  return {20,  {{"d",2},{"m",2},{"qs",16}}};               // Q4_1
        case 6:  return {22,  {{"d",2},{"qh",4},{"qs",16}}};              // Q5_0
        case 7:  return {24,  {{"d",2},{"m",2},{"qh",4},{"qs",16}}};      // Q5_1
        case 8:  return {34,  {{"d",2},{"qs",32}}};                       // Q8_0
        case 9:  return {36,  {{"d",2},{"m",2},{"qs",32}}};               // Q8_1 (d+m+32)
        case 10: return {84,  {{"scales",16},{"qs",64},{"d",2},{"dmin",2}}}; // Q2_K
        case 11: return {110, {{"hmask",32},{"qs",64},{"scales",12},{"d",2}}}; // Q3_K
        case 12: return {144, {{"d",2},{"dmin",2},{"scales",12},{"qs",128}}};   // Q4_K
        case 13: return {176, {{"d",2},{"dmin",2},{"scales",12},{"qh",32},{"qs",128}}}; // Q5_K
        case 14: return {210, {{"ql",128},{"qh",64},{"scales",16},{"d",2}}};     // Q6_K
        default: return {}; // F32/F16 handled by the generic path
    }
}

// ---------------------------------------------------------------------------
// zlib helpers (one-shot, bounded).
// ---------------------------------------------------------------------------
inline std::vector<uint8_t> ZComp(const uint8_t* p, size_t n) {
    if (n > static_cast<size_t>(0xffffffffu)) throw std::length_error("zlib input too large");
    uLongf cap = compressBound(static_cast<uLong>(n));
    std::vector<uint8_t> out(static_cast<size_t>(cap));
    if (compress2(out.data(), &cap, p, static_cast<uLong>(n), Z_BEST_COMPRESSION) != Z_OK)
        throw std::runtime_error("zlib compress failed");
    out.resize(static_cast<size_t>(cap));
    return out;
}
inline std::vector<uint8_t> ZDecomp(const uint8_t* p, size_t n, size_t expect) {
    std::vector<uint8_t> out(expect);
    uLongf got = static_cast<uLongf>(expect);
    if (expect == 0) return out;
    if (uncompress(out.data(), &got, p, static_cast<uLong>(n)) != Z_OK || got != expect)
        throw std::runtime_error("zlib decompress failed / size mismatch");
    out.resize(static_cast<size_t>(got));
    return out;
}

// ---------------------------------------------------------------------------
// V2 encode/decode for a single packed-quant tensor.
// ---------------------------------------------------------------------------
// Deinterleaves each block into per-field streams, compresses each stream,
// and stores the stream directory. Falls back to raw/zlib if that is smaller.
struct V2Tensor {
    uint32_t type = 0;
    uint64_t plain_size = 0;
    uint32_t block_bytes = 0;
    uint32_t n_blocks = 0;
    // Directory: for each field, its raw length and compressed bytes.
    struct Stream { std::string name; uint32_t raw_len = 0; std::vector<uint8_t> comp; };
    std::vector<Stream> streams;
    // Fallback encodings.
    uint8_t method = 0; // 0=raw, 1=zlib whole, 2=deinterleaved
    std::vector<uint8_t> raw_or_zlib; // used when method 0/1
};

inline V2Tensor EncodeV2(const uint8_t* data, size_t size, uint32_t type) {
    V2Tensor t;
    t.type = type;
    t.plain_size = size;
    const QLayout lay = GetQLayout(type);
    if (lay.block_bytes == 0 || size % lay.block_bytes != 0)
        throw std::invalid_argument("V2: not a packed quant tensor or bad size");

    t.block_bytes = lay.block_bytes;
    t.n_blocks = static_cast<uint32_t>(size / lay.block_bytes);

    // Deinterleave: stream[j] accumulates field j bytes across all blocks.
    std::vector<std::vector<uint8_t>> streams(lay.fields.size());
    std::vector<uint32_t> fieldOff(lay.fields.size(), 0);
    for (const auto& f : lay.fields) streams[&f - lay.fields.data()].reserve(
        static_cast<size_t>(t.n_blocks) * f.bytes);

    for (uint32_t b = 0; b < t.n_blocks; ++b) {
        const uint8_t* blk = data + static_cast<size_t>(b) * lay.block_bytes;
        uint32_t off = 0;
        for (size_t j = 0; j < lay.fields.size(); ++j) {
            const uint32_t fb = lay.fields[j].bytes;
            streams[j].insert(streams[j].end(), blk + off, blk + off + fb);
            off += fb;
        }
        if (off != lay.block_bytes) throw std::runtime_error("V2: field layout mismatch");
    }

    // Compress each stream; keep the smaller of {compressed, raw}.
    size_t total = 0;
    for (size_t j = 0; j < streams.size(); ++j) {
        V2Tensor::Stream s;
        s.name = lay.fields[j].name;
        s.raw_len = static_cast<uint32_t>(streams[j].size());
        auto comp = ZComp(streams[j].data(), streams[j].size());
        if (comp.size() < streams[j].size()) s.comp = std::move(comp);
        else s.comp = std::move(streams[j]); // raw fallback per stream
        total += s.comp.size();
        t.streams.push_back(std::move(s));
    }

    // Best-of against whole-tensor zlib.
    auto whole = ZComp(data, size);
    if (whole.size() < total) {
        t.method = 1;
        t.raw_or_zlib = std::move(whole);
        t.streams.clear();
    } else {
        t.method = 2;
    }
    return t;
}

inline std::vector<uint8_t> DecodeV2(const V2Tensor& t) {
    const QLayout lay = GetQLayout(t.type);
    if (lay.block_bytes == 0) throw std::runtime_error("V2: unknown type on decode");
    std::vector<uint8_t> out(t.plain_size);

    if (t.method == 0) {
        if (t.raw_or_zlib.size() != t.plain_size) throw std::runtime_error("V2: raw size mismatch");
        std::memcpy(out.data(), t.raw_or_zlib.data(), t.plain_size);
        return out;
    }
    if (t.method == 1) {
        return ZDecomp(t.raw_or_zlib.data(), t.raw_or_zlib.size(), t.plain_size);
    }
    // method 2: re-interleave deinterleaved streams.
    if (t.streams.size() != lay.fields.size())
        throw std::runtime_error("V2: stream count mismatch");
    std::vector<std::vector<uint8_t>> streams(lay.fields.size());
    for (size_t j = 0; j < t.streams.size(); ++j) {
        const auto& s = t.streams[j];
        if (s.comp.size() == static_cast<size_t>(s.raw_len)) {
            streams[j] = s.comp; // stored raw
        } else {
            streams[j] = ZDecomp(s.comp.data(), s.comp.size(), s.raw_len);
        }
    }
    for (uint32_t b = 0; b < t.n_blocks; ++b) {
        uint8_t* blk = out.data() + static_cast<size_t>(b) * lay.block_bytes;
        uint32_t off = 0;
        for (size_t j = 0; j < lay.fields.size(); ++j) {
            const uint32_t fb = lay.fields[j].bytes;
            const uint8_t* src = streams[j].data() + static_cast<size_t>(b) * fb;
            std::memcpy(blk + off, src, fb);
            off += fb;
        }
    }
    return out;
}

// Portable serialize/deserialize for V2Tensor (little-endian, RWT2).
namespace detail {
inline void Put32(std::vector<uint8_t>& o, uint32_t v) { for (int i=0;i<4;++i) o.push_back((v>>(8*i))&0xff); }
inline void Put64(std::vector<uint8_t>& o, uint64_t v) { for (int i=0;i<8;++i) o.push_back((v>>(8*i))&0xff); }
struct Rd {
    const std::vector<uint8_t>& b; size_t p=0;
    uint32_t U32(){ uint32_t v=0; for(int i=0;i<4;++i) v|=uint32_t(b.at(p++))<<(8*i); return v; }
    uint64_t U64(){ uint64_t v=0; for(int i=0;i<8;++i) v|=uint64_t(b.at(p++))<<(8*i); return v; }
    std::string Str(){ uint64_t n=U64(); if(n>4096) throw std::runtime_error("V2: str too long"); std::string s(n,'\0'); for(uint64_t i=0;i<n;++i) s[i]=char(b.at(p++)); return s; }
    std::vector<uint8_t> Blob(){ uint32_t n=U32(); if(p+n>b.size()) throw std::runtime_error("V2: blob truncated"); std::vector<uint8_t> v(b.begin()+p,b.begin()+p+n); p+=n; return v; }
};
} // namespace detail

inline std::vector<uint8_t> SerializeV2(const V2Tensor& t) {
    std::vector<uint8_t> o;
    const uint32_t magic = 0x32545752u; // RWT2
    detail::Put32(o, magic);
    detail::Put32(o, t.type);
    detail::Put64(o, t.plain_size);
    detail::Put32(o, t.block_bytes);
    detail::Put32(o, t.n_blocks);
    o.push_back(t.method);
    if (t.method == 0 || t.method == 1) {
        detail::Put32(o, static_cast<uint32_t>(t.raw_or_zlib.size()));
        o.insert(o.end(), t.raw_or_zlib.begin(), t.raw_or_zlib.end());
    } else {
        detail::Put32(o, static_cast<uint32_t>(t.streams.size()));
        for (const auto& s : t.streams) {
            detail::Put64(o, s.name.size());
            o.insert(o.end(), s.name.begin(), s.name.end());
            detail::Put32(o, s.raw_len);
            detail::Put32(o, static_cast<uint32_t>(s.comp.size()));
            o.insert(o.end(), s.comp.begin(), s.comp.end());
        }
    }
    return o;
}

inline V2Tensor DeserializeV2(const std::vector<uint8_t>& b) {
    detail::Rd r{b};
    if (r.U32() != 0x32545752u) throw std::runtime_error("V2: bad magic");
    V2Tensor t;
    t.type = r.U32();
    t.plain_size = r.U64();
    t.block_bytes = r.U32();
    t.n_blocks = r.U32();
    t.method = b.at(r.p++);
    if (t.method > 2) throw std::runtime_error("V2: bad method");
    if (t.method == 0 || t.method == 1) {
        t.raw_or_zlib = r.Blob();
    } else {
        uint32_t ns = r.U32();
        for (uint32_t i = 0; i < ns; ++i) {
            V2Tensor::Stream s;
            s.name = r.Str();
            s.raw_len = r.U32();
            s.comp = r.Blob();
            t.streams.push_back(std::move(s));
        }
    }
    return t;
}

} // namespace rawrxd::weights::v2

#endif // RAWRXD_TENSORAWARE_LOSSLESS_V2_HPP