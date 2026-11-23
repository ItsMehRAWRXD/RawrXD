#pragma once
// Native, dependency-free tensor storage optimizer. No changes to GGUF wire types.
// Lossless byte RLE is a private storage representation, not a GGUF quantization.
// F32->F16/BF16 are lossy; callers opt in and supply a maximum absolute error.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <limits>
#include <stdexcept>
#include <cmath>

namespace RawrXD { namespace TensorCompression {
enum class Encoding : uint8_t { Raw = 0, RLE = 1, F16 = 2, BF16 = 3 };
struct Result {
    Encoding encoding = Encoding::Raw;
    uint64_t original_bytes = 0;
    std::vector<uint8_t> payload;
};
inline uint32_t Bits(float x) { uint32_t u; std::memcpy(&u, &x, 4); return u; }
inline float Float(uint32_t u) { float f; std::memcpy(&f, &u, 4); return f; }
// IEEE-754 binary32 -> binary16, round-to-nearest ties-to-even; preserve NaN.
inline uint16_t ToHalf(float x) {
    const uint32_t u=Bits(x), sign=(u>>16)&0x8000u, exp=(u>>23)&255u, mant=u&0x7fffffu;
    if (exp==255) return uint16_t(sign | (mant ? (0x7c00u | (mant>>13) | 0x0200u) : 0x7c00u));
    int32_t e=int32_t(exp)-127+15;
    if (e>=31) return uint16_t(sign|0x7c00u);
    if (e<=0) {
        if (e< -10) return uint16_t(sign);
        uint32_t m=mant|0x800000u;
        const unsigned shift=unsigned(14-e);
        uint32_t q=m>>shift, rem=m&((1u<<shift)-1u), mid=1u<<(shift-1);
        if (rem>mid || (rem==mid && (q&1u))) ++q;
        return uint16_t(sign|q);
    }
    uint32_t q=mant>>13, rem=mant&0x1fffu;
    if (rem>0x1000u || (rem==0x1000u && (q&1u))) ++q;
    if (q==0x400u) { q=0; ++e; if(e>=31) return uint16_t(sign|0x7c00u); }
    return uint16_t(sign|(uint32_t(e)<<10)|q);
}
// IEEE-754 binary32 -> bfloat16, round-to-nearest ties-to-even.
inline uint16_t ToBFloat16(float x) {
    const uint32_t u=Bits(x);
    // Preserve infinities and ensure every NaN remains a quiet NaN.
    if ((u&0x7f800000u)==0x7f800000u) {
        uint16_t h=uint16_t(u>>16);
        if (u&0x007fffffu) h=uint16_t(h|0x0040u);
        return h;
    }
    const uint32_t lsb=(u>>16)&1u;
    return uint16_t((u+0x7fffu+lsb)>>16);
}
inline float FromBFloat16(uint16_t h) {
    return Float(uint32_t(h)<<16);
}
inline float FromHalf(uint16_t h) {
    uint32_t sign=(uint32_t(h&0x8000u)<<16), m=h&1023u, e=(h>>10)&31u;
    if (e==31) return Float(sign|0x7f800000u|(m<<13));
    if (e==0) {
        if (!m) return Float(sign);
        int32_t ex=-14;
        while ((m&0x400u)==0) { m<<=1; --ex; }
        return Float(sign|(uint32_t(ex+127)<<23)|((m&1023u)<<13));
    }
    return Float(sign|((e+112u)<<23)|(m<<13));
}
inline Result Encode(const void* data, size_t bytes, bool allow_fp16=false, float max_abs_error=0.0f, bool allow_bf16=false) {
    if (bytes && !data) throw std::invalid_argument("null tensor");
    if (!std::isfinite(max_abs_error) || max_abs_error<0) throw std::invalid_argument("invalid tolerance");
    const auto* p=static_cast<const uint8_t*>(data);
    Result best; best.original_bytes=bytes;
    if (bytes) best.payload.assign(p,p+bytes);
    // Encode runs as [count:1][value:1]. Only adopt if strictly smaller.
    if (bytes>2) {
        std::vector<uint8_t> rle;
        for (size_t i=0;i<bytes;) {
            uint8_t n=1;
            while (i+n<bytes && n<255 && p[i+n]==p[i]) ++n;
            rle.push_back(n); rle.push_back(p[i]); i+=n;
            if (rle.size()>=best.payload.size()) break;
        }
        if (rle.size()<best.payload.size()) { best.encoding=Encoding::RLE; best.payload=std::move(rle); }
    }
    if (allow_fp16 && bytes%4==0 && bytes/2<best.payload.size()) {
        std::vector<uint8_t> half(bytes/2);
        bool valid=true;
        for (size_t i=0;i<bytes/4;++i) {
            float f; std::memcpy(&f,p+4*i,4);
            uint16_t h=ToHalf(f);
            float back=FromHalf(h);
            // NaN/Inf excluded from lossy path: preserve special payloads in raw representation.
            uint32_t b=Bits(f);
            if ((b&0x7f800000u)==0x7f800000u) { valid=false; break; }
            float delta=back-f;
            if (!(delta<=max_abs_error && delta>=-max_abs_error)) { valid=false; break; }
            half[2*i]=uint8_t(h); half[2*i+1]=uint8_t(h>>8);
        }
        if (valid) { best.encoding=Encoding::F16; best.payload=std::move(half); }
    }
    if (allow_bf16 && bytes%4==0 && bytes/2<best.payload.size()) {
        std::vector<uint8_t> half(bytes/2);
        bool valid=true;
        for (size_t i=0;i<bytes/4;++i) {
            float f; std::memcpy(&f,p+4*i,4);
            const uint32_t bits=Bits(f);
            // Keep NaN/Inf payloads in the original representation.
            if ((bits&0x7f800000u)==0x7f800000u) { valid=false; break; }
            const uint16_t h=ToBFloat16(f);
            const float back=FromBFloat16(h);
            const float delta=back-f;
            if (!(delta<=max_abs_error && delta>=-max_abs_error)) { valid=false; break; }
            half[2*i]=uint8_t(h); half[2*i+1]=uint8_t(h>>8);
        }
        if (valid) { best.encoding=Encoding::BF16; best.payload=std::move(half); }
    }
    return best;
}
// Per-tensor adaptive F32 storage: lossless RLE is always considered;
// F16 is preferred when valid, with BF16 as the wider-exponent fallback.
// The original bytes remain the fallback whenever neither meets the budget.
inline Result EncodeAdaptiveF32(const float* values,size_t count,float max_abs_error) {
    if(count && !values) throw std::invalid_argument("null F32 tensor");
    if(count>std::numeric_limits<size_t>::max()/sizeof(float))
        throw std::length_error("F32 tensor size overflow");
    return Encode(values,count*sizeof(float),true,max_abs_error,true);
}
// Decode directly into caller-owned storage. This avoids an intermediate
// allocation when a runtime must materialize one tile/row into an existing
// scratch buffer. The destination is unchanged on all preflight failures.
inline void DecodeInto(const Result& r, void* destination, size_t destination_bytes) {
    if (r.original_bytes>std::numeric_limits<size_t>::max())
        throw std::length_error("size overflow");
    const size_t n=static_cast<size_t>(r.original_bytes);
    if (destination_bytes!=n) throw std::invalid_argument("destination size mismatch");
    if (n && !destination) throw std::invalid_argument("null decode destination");
    auto* out=static_cast<uint8_t*>(destination);
    if (r.encoding==Encoding::Raw) {
        if (r.payload.size()!=n) throw std::invalid_argument("raw size mismatch");
        if(n) std::memcpy(out,r.payload.data(),n);
        return;
    }
    if (r.encoding==Encoding::RLE) {
        if (r.payload.size()%2) throw std::invalid_argument("malformed RLE");
        size_t total=0;
        for(size_t i=0;i<r.payload.size();i+=2) {
            const size_t count=r.payload[i];
            if (!count || count>n-total) throw std::invalid_argument("RLE overflow");
            total+=count;
        }
        if(total!=n) throw std::invalid_argument("RLE decoded size mismatch");
        size_t written=0;
        for(size_t i=0;i<r.payload.size();i+=2) {
            const size_t count=r.payload[i];
            std::memset(out+written,r.payload[i+1],count);
            written+=count;
        }
        return;
    }
    if (r.encoding==Encoding::F16 || r.encoding==Encoding::BF16) {
        if (n%4 || r.payload.size()!=n/2)
            throw std::invalid_argument("16-bit float size mismatch");
        for(size_t i=0;i<n/4;++i) {
            const uint16_t h=uint16_t(r.payload[2*i])|
                             (uint16_t(r.payload[2*i+1])<<8);
            const float f=r.encoding==Encoding::F16?FromHalf(h):FromBFloat16(h);
            std::memcpy(out+4*i,&f,4);
        }
        return;
    }
    throw std::invalid_argument("unknown encoding");
}
inline std::vector<uint8_t> Decode(const Result& r) {
    if (r.original_bytes>std::numeric_limits<size_t>::max())
        throw std::length_error("size overflow");
    std::vector<uint8_t> out(static_cast<size_t>(r.original_bytes));
    DecodeInto(r,out.data(),out.size());
    return out;
}

// Chunked compressed F32 residency. Each chunk is independently encoded, so
// inference callers can request a row/tile without expanding the full tensor.
// This is a private runtime representation; it never changes GGUF wire types.
class ChunkedF32Storage {
public:
    ChunkedF32Storage() = default;
    static ChunkedF32Storage Build(const float* values,size_t count,
                                   float max_abs_error,size_t chunk_elements=4096) {
        if(count && !values) throw std::invalid_argument("null F32 tensor");
        if(!chunk_elements) throw std::invalid_argument("zero chunk size");
        if(count>std::numeric_limits<size_t>::max()/sizeof(float))
            throw std::length_error("F32 tensor size overflow");
        ChunkedF32Storage result;
        result.element_count_=count;
        result.chunk_elements_=chunk_elements;
        result.chunks_.reserve(count/chunk_elements+(count%chunk_elements!=0));
        for(size_t offset=0;offset<count;) {
            const size_t n=(count-offset<chunk_elements)?count-offset:chunk_elements;
            result.chunks_.push_back(EncodeAdaptiveF32(values+offset,n,max_abs_error));
            offset+=n;
        }
        return result;
    }
    size_t size() const noexcept { return element_count_; }
    size_t chunkElements() const noexcept { return chunk_elements_; }
    size_t chunkCount() const noexcept { return chunks_.size(); }
    size_t storedBytes() const noexcept {
        size_t total=0;
        for(const auto& c:chunks_) {
            if(c.payload.size()>std::numeric_limits<size_t>::max()-total)
                return std::numeric_limits<size_t>::max();
            total+=c.payload.size();
        }
        return total;
    }
    // Read [first, first+count) into caller-owned F32 memory. Only intersecting
    // chunks are decoded; out-of-range requests fail before writing anything.
    void ReadRange(size_t first,size_t count,float* destination) const {
        std::vector<uint8_t> scratch;
        ReadRange(first,count,destination,scratch);
    }
    void ReadRange(size_t first,size_t count,float* destination,
                   std::vector<uint8_t>& scratch) const {
        if(first>element_count_ || count>element_count_-first)
            throw std::out_of_range("compressed tensor range");
        if(count && !destination) throw std::invalid_argument("null range destination");
        if(!count) return;
        const size_t end=first+count;
        const size_t first_chunk=first/chunk_elements_;
        const size_t last_chunk=(end-1)/chunk_elements_;
        for(size_t ci=first_chunk;ci<=last_chunk;++ci) {
            const Result& encoded=chunks_[ci];
            const size_t chunk_first=ci*chunk_elements_;
            const size_t chunk_count=static_cast<size_t>(encoded.original_bytes/sizeof(float));
            scratch.resize(static_cast<size_t>(encoded.original_bytes));
            DecodeInto(encoded,scratch.data(),scratch.size());
            const size_t copy_first=first>chunk_first?first:chunk_first;
            const size_t chunk_end=chunk_first+chunk_count;
            const size_t copy_end=end<chunk_end?end:chunk_end;
            const size_t n=copy_end-copy_first;
            std::memcpy(destination+(copy_first-first),
                        scratch.data()+(copy_first-chunk_first)*sizeof(float),
                        n*sizeof(float));
        }
    }
private:
    size_t element_count_=0;
    size_t chunk_elements_=4096;
    std::vector<Result> chunks_;
};

}} // namespace RawrXD::TensorCompression
