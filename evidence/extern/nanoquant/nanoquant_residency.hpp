#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <limits>

namespace rawrxd::nanoquant {
// Lossless byte-stream codec for already-quantized GGUF weight payloads.
// Format: literal [0..127] => length=tag+1; repeat [128..255] => length=(tag&127)+3.
// A repeated byte follows a repeat tag. Literal bytes follow a literal tag.
// Designed for exact round-trip, not guaranteed compression of high-entropy weights.
inline std::vector<uint8_t> encode(const uint8_t* src, size_t n) {
    if (!src && n) throw std::invalid_argument("null source");
    std::vector<uint8_t> out;
    for (size_t i=0;i<n;) {
        size_t run=1;
        while (i+run<n && run<130 && src[i+run]==src[i]) ++run;
        if (run>=3) {
            out.push_back(static_cast<uint8_t>(0x80u | (run-3)));
            out.push_back(src[i]); i+=run;
        } else {
            const size_t start=i; i+=run;
            while (i<n && i-start<128) {
                size_t r=1;
                while (i+r<n && r<3 && src[i+r]==src[i]) ++r;
                if (r>=3) break;
                i+=r;
            }
            out.push_back(static_cast<uint8_t>(i-start-1));
            out.insert(out.end(),src+start,src+i);
        }
    }
    return out;
}
inline bool decode(const uint8_t* src, size_t n, uint8_t* dst, size_t expected) {
    if ((!src && n) || (!dst && expected)) return false;
    size_t i=0,j=0;
    while (i<n) {
        const uint8_t tag=src[i++];
        const size_t count=(tag&0x80u)?size_t(tag&0x7fu)+3:size_t(tag)+1;
        if (count>expected-j) return false;
        if (tag&0x80u) {
            if (i==n) return false;
            std::memset(dst+j,src[i++],count);
        } else {
            if (count>n-i) return false;
            std::memcpy(dst+j,src+i,count); i+=count;
        }
        j+=count;
    }
    return j==expected;
}
struct Plan {
    size_t original_bytes=0, stored_bytes=0;
    bool compressed=false;
    std::vector<uint8_t> payload;
};
inline Plan plan(const uint8_t* src,size_t n) {
    Plan p; p.original_bytes=n;
    auto packed=encode(src,n);
    p.compressed=packed.size()<n;
    if (p.compressed) p.payload=std::move(packed);
    else if (n) p.payload.assign(src,src+n);
    p.stored_bytes=p.payload.size();
    return p;
}
inline bool restore(const Plan& p, uint8_t* dst,size_t capacity) {
    if (capacity!=p.original_bytes) return false;
    if (!p.compressed) {
        if (p.payload.size()!=capacity || (!dst && capacity)) return false;
        if (capacity) std::memcpy(dst,p.payload.data(),capacity);
        return true;
    }
    return decode(p.payload.data(),p.payload.size(),dst,capacity);
}
} // namespace rawrxd::nanoquant
