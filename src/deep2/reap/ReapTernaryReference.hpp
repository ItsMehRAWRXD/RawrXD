#pragma once
// Explicit ternary 1.5-bit reference format. NOT a GGUF quantization decoder.
// Four trits (0,1,2) are packed in one byte using base-3 digits (81 states).
// Actual density = 2 bits/value at byte granularity for groups of 4,
// approaching log2(3)=1.585 bits/value only with larger blocks/entropy coding.
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>
namespace Deep2::ReapRom {
inline std::vector<uint8_t> PackTernary4(const std::vector<int8_t>& values) {
    std::vector<uint8_t> packed;
    packed.reserve((values.size()+3)/4);
    for(size_t i=0;i<values.size();i+=4) {
        uint32_t code=0, radix=1;
        for(size_t j=0;j<4;++j) {
            const int v=(i+j<values.size())?values[i+j]:0;
            if(v<-1 || v>1) throw std::invalid_argument("non-ternary value");
            code+=static_cast<uint32_t>(v+1)*radix;
            radix*=3;
        }
        packed.push_back(static_cast<uint8_t>(code));
    }
    return packed;
}
inline std::vector<int8_t> UnpackTernary4(const std::vector<uint8_t>& packed,
                                          size_t count) {
    if(count>packed.size()*4 || (count+3)/4!=packed.size())
        throw std::invalid_argument("packed ternary length mismatch");
    std::vector<int8_t> out;
    out.reserve(count);
    for(uint8_t b:packed) {
        if(b>=81) throw std::invalid_argument("invalid ternary code");
        uint32_t code=b;
        for(size_t j=0;j<4 && out.size()<count;++j) {
            out.push_back(static_cast<int8_t>(code%3)-1);
            code/=3;
        }
    }
    return out;
}
} // namespace Deep2::ReapRom
