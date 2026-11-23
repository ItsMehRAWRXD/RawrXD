#pragma once
// IEEE-754 binary32 -> binary16, round-to-nearest, ties-to-even.
// Integer-only implementation; independent of host FPU rounding mode.
#include <cstdint>
#include <cstring>
namespace RawrXD { namespace REAP {
inline uint16_t Float32BitsToFloat16(uint32_t bits) {
    const uint32_t sign=(bits>>16)&0x8000u;
    const uint32_t exp=(bits>>23)&0xffu;
    const uint32_t fraction=bits&0x7fffffu;
    if(exp==255) {
        if(!fraction)return static_cast<uint16_t>(sign|0x7c00u);
        // Preserve payload when representable, force quiet NaN.
        return static_cast<uint16_t>(sign|0x7c00u|0x0200u|(fraction>>13));
    }
    const int32_t e=static_cast<int32_t>(exp)-127+15;
    if(e>=31)return static_cast<uint16_t>(sign|0x7c00u);
    if(e<=0) {
        if(e< -10)return static_cast<uint16_t>(sign);
        const uint32_t mantissa=fraction|0x800000u;
        const uint32_t shift=static_cast<uint32_t>(14-e);
        const uint32_t value=mantissa>>shift;
        const uint32_t remainder=mantissa&((1u<<shift)-1u);
        const uint32_t halfway=1u<<(shift-1u);
        return static_cast<uint16_t>(sign|value+
            ((remainder>halfway||(remainder==halfway&&(value&1u)))?1u:0u));
    }
    const uint32_t value=(static_cast<uint32_t>(e)<<10)|(fraction>>13);
    const uint32_t remainder=fraction&0x1fffu;
    const uint32_t rounded=value+
        ((remainder>0x1000u||(remainder==0x1000u&&(value&1u)))?1u:0u);
    return static_cast<uint16_t>(sign|rounded);
}
// Expand IEEE-754 binary16 exactly into binary32 bits (no rounding).
inline uint32_t Float16ToFloat32Bits(uint16_t half) {
    const uint32_t sign=(uint32_t(half&0x8000u)<<16);
    const uint32_t exponent=(half>>10)&0x1fu;
    uint32_t fraction=half&0x03ffu;
    if(exponent==31u)
        return sign|0x7f800000u|(fraction<<13);
    if(exponent==0u) {
        if(!fraction)return sign;
        int32_t e=-14;
        while((fraction&0x0400u)==0u){fraction<<=1;--e;}
        fraction&=0x03ffu;
        return sign|(uint32_t(e+127)<<23)|(fraction<<13);
    }
    return sign|((exponent+112u)<<23)|(fraction<<13);
}
inline float Float16ToFloat32(uint16_t half) {
    const uint32_t bits=Float16ToFloat32Bits(half);
    float value=0.0f;
    std::memcpy(&value,&bits,sizeof(value));
    return value;
}
inline uint16_t Float32ToFloat16(float value) {
    static_assert(sizeof(float)==sizeof(uint32_t),"requires IEEE-754 binary32");
    uint32_t bits=0;
    std::memcpy(&bits,&value,sizeof(bits));
    return Float32BitsToFloat16(bits);
}
}} // namespace RawrXD::REAP
