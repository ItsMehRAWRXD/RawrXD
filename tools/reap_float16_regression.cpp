#include "../src/reap/NativeFloat16.hpp"
#include <cstdint>
#include <iostream>
using RawrXD::REAP::Float32BitsToFloat16;
using RawrXD::REAP::Float16ToFloat32Bits;
int main(){
    int fails=0;
    auto check=[&](uint32_t bits,uint16_t expected,const char* label){
        const uint16_t got=Float32BitsToFloat16(bits);
        std::cout<<(got==expected?"PASS ":"FAIL ")<<label<<"\n";
        if(got!=expected)++fails;
    };
    check(0x00000000u,0x0000u,"positive_zero");
    check(0x80000000u,0x8000u,"negative_zero");
    check(0x3f800000u,0x3c00u,"one");
    check(0xbf800000u,0xbc00u,"negative_one");
    check(0x7f800000u,0x7c00u,"positive_infinity");
    check(0xff800000u,0xfc00u,"negative_infinity");
    check(0x7fc00000u,0x7e00u,"quiet_nan");
    check(0x33800000u,0x0001u,"smallest_half_subnormal");
    check(0x33000000u,0x0000u,"subnormal_halfway_ties_even");
    check(0x387fc000u,0x03ffu,"largest_half_subnormal");
    check(0x38800000u,0x0400u,"smallest_half_normal");
    check(0x477fe000u,0x7bffu,"largest_half_finite");
    check(0x47800000u,0x7c00u,"overflow_to_infinity");
    check(0x3f801000u,0x3c00u,"normal_halfway_ties_even_down");
    check(0x3f803000u,0x3c02u,"normal_halfway_ties_even_up");
    check(0x3f802000u,0x3c01u,"normal_exact_next");
    // Exhaustively verify all 65,536 half bit patterns. NaN payloads are
    // intentionally quieted by the F32->F16 encoder; all non-NaNs must
    // round-trip bit-exactly, including signed zero and subnormals.
    unsigned roundtripFailures=0;
    for(uint32_t half=0;half<=0xffffu;++half) {
        const uint16_t h=static_cast<uint16_t>(half);
        const uint32_t exp=(half>>10)&31u;
        const uint32_t frac=half&1023u;
        const uint16_t roundtrip=Float32BitsToFloat16(Float16ToFloat32Bits(h));
        const uint16_t expected=(exp==31u&&frac!=0u)?
            static_cast<uint16_t>(h|0x0200u):h;
        if(roundtrip!=expected)++roundtripFailures;
    }
    std::cout<<"HALF_ROUNDTRIP_MISMATCHES="<<roundtripFailures<<"\n";
    if(roundtripFailures)++fails;
    std::cout<<"REAP_F16_RESULT="<<(fails?"FAIL":"PASS")
             <<" failures="<<fails<<"\n";
    return fails?1:0;
}
