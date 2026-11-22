#include "deep2/ReapQ4KToQ2K.hpp"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <limits>
using namespace Deep2::ReapQuant;

int main() {
    unsigned pass=0,fail=0;
    auto check=[&](bool ok,const char* label) {
        if(ok)++pass;
        else {++fail;std::printf("FAIL %s\n",label);}
    };
    // Every finite, nonnegative binary16 value must round-trip exactly.
    for(uint32_t bits=0;bits<0x7c00u;++bits) {
        uint16_t encoded=0xffffu;
        const float value=Half(static_cast<uint16_t>(bits));
        if(!PositiveHalf(value,encoded)||encoded!=bits) {
            ++fail;
            std::printf("FAIL half roundtrip bits=0x%04x encoded=0x%04x\n",
                        unsigned(bits),unsigned(encoded));
            break;
        }
        ++pass;
    }
    uint16_t encoded=0xffffu;
    check(PositiveHalf(0.0,encoded)&&encoded==0,"positive zero");
    check(PositiveHalf(65504.0,encoded)&&encoded==0x7bffu,"largest finite half");
    check(!PositiveHalf(65505.0,encoded),"reject out-of-range");
    check(!PositiveHalf(-1.0,encoded),"reject negative");
    check(!PositiveHalf(std::numeric_limits<double>::infinity(),encoded),"reject infinity");
    check(!PositiveHalf(std::numeric_limits<double>::quiet_NaN(),encoded),"reject nan");
    check(PositiveHalf(std::ldexp(1.0,-24),encoded)&&encoded==1,"smallest subnormal");
    check(PositiveHalf(std::ldexp(1.0,-25),encoded)&&encoded==0,"subnormal tie to even zero");
    check(PositiveHalf(std::ldexp(3.0,-25),encoded)&&encoded==2,"subnormal tie to even two");
    check(PositiveHalf(std::ldexp(1.0,-14),encoded)&&encoded==0x0400u,"smallest normal");
    check(PositiveHalf(std::ldexp(1.0,-14)-std::ldexp(1.0,-25),encoded)&&
          encoded==0x0400u,"normal boundary ties to even");
    std::printf("PASS_COUNT=%u FAIL_COUNT=%u\n",pass,fail);
    return fail?1:0;
}
