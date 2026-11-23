#pragma once
// Native, bounded-memory FP32 -> FP16 accuracy audit for tensor payloads.
// The audit never claims inference parity; it measures elementwise conversion.
#include "NativeFloat16.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <string>

namespace RawrXD { namespace REAP {
struct F16Accuracy {
    uint64_t elements=0, finite=0, nonfinite=0, overflowed=0;
    double max_abs=0.0, max_rel=0.0, rms_abs=0.0;
};
inline bool AuditF32ToF16(const std::string& input,
                          const std::string& output,
                          uint64_t inputOffset,uint64_t outputOffset,
                          uint64_t elements,F16Accuracy& result) {
    result={};
    if(elements==0 || elements>UINT64_MAX/4 ||
       inputOffset>UINT64_MAX-elements*4 ||
       outputOffset>UINT64_MAX-elements*2 ||
       inputOffset+elements*4>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()) ||
       outputOffset+elements*2>static_cast<uint64_t>(std::numeric_limits<std::streamoff>::max()))
        return false;
    std::ifstream src(input,std::ios::binary),dst(output,std::ios::binary);
    if(!src||!dst)return false;
    src.seekg(static_cast<std::streamoff>(inputOffset));
    dst.seekg(static_cast<std::streamoff>(outputOffset));
    if(!src||!dst)return false;
    unsigned char f32[16384],f16[8192];
    long double sumSquares=0;
    uint64_t remaining=elements;
    while(remaining) {
        const size_t n=static_cast<size_t>(std::min<uint64_t>(remaining,4096));
        if(!src.read(reinterpret_cast<char*>(f32),static_cast<std::streamsize>(n*4)) ||
           !dst.read(reinterpret_cast<char*>(f16),static_cast<std::streamsize>(n*2)))
            return false;
        for(size_t i=0;i<n;++i) {
            const size_t j=i*4,k=i*2;
            const uint32_t bits=uint32_t(f32[j])|(uint32_t(f32[j+1])<<8)|
                (uint32_t(f32[j+2])<<16)|(uint32_t(f32[j+3])<<24);
            const uint16_t half=uint16_t(f16[k])|(uint16_t(f16[k+1])<<8);
            if(half!=Float32BitsToFloat16(bits))return false;
            const uint32_t decoded=Float16ToFloat32Bits(half);
            float original=0.0f,reconstructed=0.0f;
            std::memcpy(&original,&bits,4);
            std::memcpy(&reconstructed,&decoded,4);
            if(!std::isfinite(original)) {
                ++result.nonfinite;
                continue;
            }
            if(!std::isfinite(reconstructed)) {
                ++result.overflowed;
                continue;
            }
            const double absError=std::abs(double(original)-double(reconstructed));
            const double relative=original==0.0f?0.0:absError/std::abs(double(original));
            result.max_abs=std::max(result.max_abs,absError);
            result.max_rel=std::max(result.max_rel,relative);
            sumSquares+=static_cast<long double>(absError)*absError;
            ++result.finite;
        }
        result.elements+=n;
        remaining-=n;
    }
    if(result.finite)
        result.rms_abs=std::sqrt(static_cast<double>(sumSquares/result.finite));
    return true;
}
}} // namespace RawrXD::REAP
