#include "deep2/ReapQ4KToQ2K.hpp"
#include <cstdio>
#include <cmath>
#include <limits>
using namespace Deep2::ReapQuant;

int main() {
    unsigned failures=0,passed=0;
    auto compare=[&](const Q4Block& source,unsigned trial) {
        Q2Block reference{},actual{};
        Error expected{},observed{};
        const bool scalar=Convert(source,reference,expected);
        const bool adaptive=ConvertAdaptive(source,actual,observed);
        const bool ok=scalar==adaptive &&
            (!scalar || (reference==actual &&
             expected.squared==observed.squared &&
             expected.signal==observed.signal &&
             expected.maxAbs==observed.maxAbs));
        if(!ok) {
            ++failures;
            std::printf("FAIL trial=%u scalar=%d adaptive=%d\n",
                        trial,int(scalar),int(adaptive));
        } else ++passed;
        return ok;
    };

    // Independent deterministic patterns vary both half scales and packed bytes.
    uint32_t state=0x9e3779b9u;
    for(unsigned trial=0;trial<4096;++trial) {
        Q4Block source{};
        const uint16_t d=static_cast<uint16_t>(0x2800u+(trial%0x1400u));
        const uint16_t m=static_cast<uint16_t>(0x2400u+((trial*17u)%0x1800u));
        StoreHalf(source.data(),d);
        StoreHalf(source.data()+2,m);
        for(unsigned i=4;i<Q4Bytes;++i) {
            state^=state<<13;state^=state>>17;state^=state<<5;
            source[i]=static_cast<uint8_t>(state);
        }
        if(!compare(source,trial))break;
    }

    // Both kernels must reject non-finite source multipliers.
    for(unsigned which=0;which<4 && !failures;++which) {
        Q4Block source{};
        StoreHalf(source.data(),0x3c00);
        StoreHalf(source.data()+2,0x3800);
        StoreHalf(source.data()+(which/2)*2,
                  static_cast<uint16_t>((which%2)?0x7e00:0x7c00));
        compare(source,4096+which);
    }

    std::printf("REAP_ADAPTIVE_AVX2=%d PASS_COUNT=%u FAIL_COUNT=%u\n",
                int(AdaptiveAvx2Available()),passed,failures);
    return failures?1:0;
}
