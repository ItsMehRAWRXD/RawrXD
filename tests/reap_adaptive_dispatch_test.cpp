#include "deep2/ReapQ4KToQ2K.hpp"
#include <cstdio>
#include <cmath>
using namespace Deep2::ReapQuant;
int main() {
    unsigned failures=0;
    for(unsigned trial=0;trial<1024;++trial) {
        Q4Block source{};
        StoreHalf(source.data(),0x3c00);
        StoreHalf(source.data()+2,0x3800);
        for(unsigned i=4;i<Q4Bytes;++i)
            source[i]=static_cast<uint8_t>((trial*37u+i*19u+(i>>3))&255u);
        Q2Block reference{},actual{};
        Error expected{},observed{};
        if(!Convert(source,reference,expected) ||
           !ConvertAdaptive(source,actual,observed) ||
           reference!=actual ||
           expected.squared!=observed.squared ||
           expected.signal!=observed.signal ||
           expected.maxAbs!=observed.maxAbs) {
            ++failures;
            std::printf("FAIL trial=%u\n",trial);
            break;
        }
    }
    std::printf("REAP_ADAPTIVE_AVX2=%d FAIL_COUNT=%u\n",
                int(AdaptiveAvx2Available()),failures);
    return failures?1:0;
}
