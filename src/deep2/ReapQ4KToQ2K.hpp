#pragma once
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstddef>
#include <limits>

#if defined(__AVX2__)
#include <immintrin.h>
#endif

namespace Deep2 { namespace ReapQuant {
constexpr size_t Elements=256, Q4Bytes=144, Q2Bytes=84;
using Values=std::array<float,Elements>;
using Q4Block=std::array<uint8_t,Q4Bytes>;
using Q2Block=std::array<uint8_t,Q2Bytes>;
inline uint16_t LoadHalf(const uint8_t* p) noexcept {
    return static_cast<uint16_t>(p[0]|(uint16_t(p[1])<<8));
}
inline void StoreHalf(uint8_t* p,uint16_t h) noexcept {
    p[0]=static_cast<uint8_t>(h);p[1]=static_cast<uint8_t>(h>>8);
}
inline float Half(uint16_t h) noexcept {
    const unsigned e=(h>>10)&31u,m=h&1023u;
    float v=e==31u?(m?std::numeric_limits<float>::quiet_NaN():std::numeric_limits<float>::infinity()):
        e?std::ldexp(float(1024u+m),int(e)-25):std::ldexp(float(m),-24);
    return h&0x8000u?-v:v;
}
// Nonnegative finite scalar, rounded to nearest binary16 with ties to even.
inline bool PositiveHalf(double x,uint16_t& h) noexcept {
    if(!std::isfinite(x)||x<0||x>65504.0)return false;
    if(x==0){h=0;return true;}
    int e=0;std::frexp(x,&e);
    const double scaled=std::ldexp(x,e<=-14?24:11-e);
    unsigned q=static_cast<unsigned>(scaled);
    const double frac=scaled-q;
    if(frac>0.5||(frac==0.5&&(q&1u)))++q;
    unsigned bits=e<=-14?q:static_cast<unsigned>((e+14)*1024)+q-1024u;
    if(bits>=0x7c00u)return false;
    h=static_cast<uint16_t>(bits);return true;
}
// Shared GGUF scale/min unpacking. Both backends use identical byte geometry.
inline void Q4ScaleMin(const uint8_t* s,unsigned g,unsigned& sc,unsigned& mn) noexcept {
    sc=g<4?s[g]&63u:(s[g+4]&15u)|((s[g-4]>>6)<<4);
    mn=g<4?s[g+4]&63u:(s[g+4]>>4)|((s[g]>>6)<<4);
}
inline bool DecodeQ4(const Q4Block& b,Values& out) noexcept {
    const float d=Half(LoadHalf(b.data())),m=Half(LoadHalf(b.data()+2));
    if(!std::isfinite(d)||!std::isfinite(m))return false;
    const auto* s=b.data()+4;
    for(unsigned g=0;g<8;++g){
        unsigned sc=0,mn=0; Q4ScaleMin(s,g,sc,mn);
        for(unsigned i=0;i<32;++i){
            const unsigned q=(b[16+(g/2)*32+i]>>(4*(g%2)))&15u;
            out[32*g+i]=d*sc*q-m*mn;
        }
    }
    return true;
}

inline bool DecodeQ2(const Q2Block& b,Values& out) noexcept {
    const float d=Half(LoadHalf(b.data()+80)),m=Half(LoadHalf(b.data()+82));
    if(!std::isfinite(d)||!std::isfinite(m))return false;
    for(unsigned g=0;g<16;++g)for(unsigned i=0;i<16;++i){
        const unsigned q=(b[16+(g/8)*32+(g%2)*16+i]>>(2*((g%8)/2)))&3u;
        out[16*g+i]=d*(b[g]&15u)*q-m*(b[g]>>4);
    }
    return true;
}
// Valid GGUF Q2_K min/max quantizer; no claim of matching the reference
// importance-aware quantizer's selection or real-model semantic quality.
inline bool EncodeQ2(const Values& in,Q2Block& out) noexcept {
    std::array<double,16> scales{},mins{};double sd=0,sm=0;
    for(unsigned g=0;g<16;++g){
        double lo=0,hi=0;
        for(unsigned i=0;i<16;++i){double x=in[16*g+i];if(!std::isfinite(x))return false;lo=std::min(lo,x);hi=std::max(hi,x);}
        scales[g]=(hi-lo)/3;mins[g]=-lo;sd=std::max(sd,scales[g]);sm=std::max(sm,mins[g]);
    }
    uint16_t hd=0,hm=0;
    if(!PositiveHalf(sd/15,hd)||!PositiveHalf(sm/15,hm))return false;
    const double d=Half(hd),m=Half(hm);
    Q2Block b{};StoreHalf(b.data()+80,hd);StoreHalf(b.data()+82,hm);
    auto rounded=[](double x,unsigned cap){return static_cast<unsigned>(std::floor(std::clamp(x,0.0,double(cap))+0.5));};
    for(unsigned g=0;g<16;++g){
        const unsigned sc=d?rounded(scales[g]/d,15):0,mn=m?rounded(mins[g]/m,15):0;
        b[g]=static_cast<uint8_t>(sc|(mn<<4));
        for(unsigned i=0;i<16;++i){
            const unsigned q=sc?rounded((double(in[16*g+i])+m*mn)/(d*sc),3):0;
            b[16+(g/8)*32+(g%2)*16+i]|=static_cast<uint8_t>(q<<(2*((g%8)/2)));
        }
    }
    out=b;return true;
}
struct Error { double squared=0,signal=0,maxAbs=0; };
inline bool Convert(const Q4Block& source,Q2Block& target,Error& error) noexcept {
    Values before{},after{};Q2Block next{};
    if(!DecodeQ4(source,before)||!EncodeQ2(before,next)||!DecodeQ2(next,after))return false;
    Error e;
    for(size_t i=0;i<Elements;++i){const double x=before[i],delta=x-after[i];e.squared+=delta*delta;e.signal+=x*x;e.maxAbs=std::max(e.maxAbs,std::abs(delta));}
    target=next;error=e;return true;
}

#if defined(__AVX2__)
// AVX2 reference-equivalent decode for the packed Q4_K layout.  The scalar
// decoder remains the numerical reference; this path is intentionally kept
// beside it so parity can be tested on the exact same block bytes.
inline bool DecodeQ4AVX2(const Q4Block& b,Values& out) noexcept {
    const float d=Half(LoadHalf(b.data())),m=Half(LoadHalf(b.data()+2));
    if(!std::isfinite(d)||!std::isfinite(m))return false;
    const __m256i mask=_mm256_set1_epi32(0x0f);
    for(unsigned g=0;g<8;++g){
        const auto* packed=b.data()+16+(g/2)*32;
        unsigned sc=0,mn=0; Q4ScaleMin(b.data()+4,g,sc,mn);
        const __m256 scale=_mm256_set1_ps(d*float(sc));
        const __m256 minimum=_mm256_set1_ps(m*float(mn));
        for(unsigned half=0;half<4;++half){
            const __m128i bytes=_mm_loadl_epi64(reinterpret_cast<const __m128i*>(packed+half*8));
            const __m256i widened=_mm256_cvtepu8_epi32(bytes);
            const __m256i shifted=(g&1u)?_mm256_srli_epi32(widened,4):widened;
            const __m256i q=_mm256_and_si256(shifted,mask);
            const __m256 values=_mm256_sub_ps(_mm256_mul_ps(_mm256_cvtepi32_ps(q),scale),minimum);
            _mm256_storeu_ps(out.data()+g*32+half*8,values);
        }
    }
    return true;
}

inline bool ConvertAVX2(const Q4Block& source,Q2Block& target,Error& error) noexcept {
    Values before{},after{};Q2Block next{};
    if(!DecodeQ4AVX2(source,before)||!EncodeQ2(before,next)||!DecodeQ2(next,after))return false;
    Error e;
    for(size_t i=0;i<Elements;++i){const double x=before[i],delta=x-after[i];e.squared+=delta*delta;e.signal+=x*x;e.maxAbs=std::max(e.maxAbs,std::abs(delta));}
    target=next;error=e;return true;
}
#endif

// GGUF Q3_K: 32 high-mask bytes, 64 low-plane bytes,
 // 12 packed signed six-bit scales, and one binary16 multiplier.
constexpr size_t Q3Bytes=110;
using Q3Block=std::array<uint8_t,Q3Bytes>;
inline bool DecodeQ3(const Q3Block& b,Values& out) noexcept {
    const float d=Half(LoadHalf(b.data()+108));
    if(!std::isfinite(d))return false;
    Values pending{};
    for(unsigned g=0;g<16;++g){
        const unsigned lo=(b[96+g%8]>>(4*(g/8)))&15u;
        const unsigned hi=(b[104+g%4]>>(2*(g/4)))&3u;
        const int scale=int(lo|(hi<<4))-32;
        for(unsigned j=0;j<16;++j){
            const unsigned i=16*g+j;
            const int q=int((b[32+(i/128)*32+i%32]>>(2*(i%128/32)))&3u)
                -((b[i%32]&(1u<<(i/32)))?0:4);
            pending[i]=d*float(scale*q);
        }
    }
    out=pending;return true;
}
// Deterministic baseline quantizer, not an importance-optimized encoder.
inline bool EncodeQ3(const Values& in,Q3Block& out) noexcept {
    std::array<double,16> scales{};
    double largest=0;
    for(unsigned g=0;g<16;++g){
        double lo=0,hi=0;
        for(unsigned j=0;j<16;++j){
            const double x=in[g*16+j];
            if(!std::isfinite(x))return false;
            lo=std::min(lo,x);hi=std::max(hi,x);
        }
        scales[g]=std::max(-lo/4,hi/3);
        largest=std::max(largest,scales[g]);
    }
    uint16_t hd=0;
    if(!PositiveHalf(largest/31,hd))return false;
    const double d=Half(hd);Q3Block b{};
    StoreHalf(b.data()+108,hd);
    for(unsigned g=0;g<16;++g){
        const int sc=d?int(std::round(std::clamp(scales[g]/d,0.0,31.0))):0;
        const unsigned packed=unsigned(sc+32);
        b[96+g%8]|=uint8_t((packed&15u)<<(4*(g/8)));
        b[104+g%4]|=uint8_t((packed>>4)<<(2*(g/4)));
        for(unsigned j=0;j<16;++j){
            const unsigned i=g*16+j;
            const int q=sc?int(std::round(std::clamp(double(in[i])/(d*sc),-4.0,3.0))):0;
            b[32+(i/128)*32+i%32]|=uint8_t((unsigned(q)&3u)<<(2*(i%128/32)));
            if(q>=0)b[i%32]|=uint8_t(1u<<(i/32));
        }
    }
    out=b;return true;
}
inline bool ConvertQ4ToQ3(const Q4Block& source,Q3Block& target,Error& error) noexcept {
    Values before{},after{};Q3Block next{};
    if(!DecodeQ4(source,before)||!EncodeQ3(before,next)||!DecodeQ3(next,after))return false;
    Error e{};
    for(size_t i=0;i<Elements;++i){
        const double x=before[i],delta=x-after[i];
        e.squared+=delta*delta;e.signal+=x*x;e.maxAbs=std::max(e.maxAbs,std::abs(delta));
    }
    target=next;error=e;return true;
}
inline bool ConvertedQ3Bytes(uint64_t rowWidth,uint64_t originalBytes,uint64_t& bytes) noexcept {
    if(!rowWidth||rowWidth%Elements||!originalBytes||originalBytes%Q4Bytes)return false;
    const uint64_t blocks=originalBytes/Q4Bytes;
    if(blocks%(rowWidth/Elements))return false;
    bytes=blocks*Q3Bytes;return true;
}

inline bool ConvertedBytes(uint64_t rowWidth,uint64_t originalBytes,uint64_t& bytes) noexcept {
    if(!rowWidth||rowWidth%Elements||!originalBytes||originalBytes%Q4Bytes)return false;
    const uint64_t blocks=originalBytes/Q4Bytes;
    if(blocks%(rowWidth/Elements))return false;
    bytes=blocks*Q2Bytes;return true;
}
} } // namespace Deep2::ReapQuant
