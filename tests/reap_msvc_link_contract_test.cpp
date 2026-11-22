#include "deep2/ReapQ4KToQ2K.hpp"
#include <cstdio>
#include <cstring>
using namespace Deep2::ReapQuant;
int main() {
#if defined(_MSC_VER) && defined(RAWRXD_REAP_MSVC_ISOLATED_AVX2) && (defined(_M_X64) || defined(_M_IX86))
    Q4Block input{};
    StoreHalf(input.data(),0x3c00u);
    for(unsigned i=4;i<16;++i)input[i]=1;
    for(unsigned i=16;i<Q4Bytes;++i)input[i]=static_cast<uint8_t>(i*13u);
    Q2Block baseline{},accelerated{};
    Error reference{},actual{};
    if(!Convert(input,baseline,reference))return 1;
    // A real call, not just a declaration: the linker must resolve the
    // isolated AVX2 object. Never execute it without OS/CPU support.
    if(AdaptiveAvx2Available()) {
        if(!ConvertMsvcAvx2(input,accelerated,actual))return 2;
        if(std::memcmp(baseline.data(),accelerated.data(),Q2Bytes)!=0 ||
           reference.squared!=actual.squared ||
           reference.signal!=actual.signal ||
           reference.maxAbs!=actual.maxAbs)return 3;
    }
    std::printf("PASS MSVC isolated AVX2 external symbol and guarded parity\n");
    return 0;
#else
    std::printf("FAIL isolated MSVC AVX2 linkage not configured\n");
    return 4;
#endif
}
