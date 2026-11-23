#include "../src/reap/NativeFloat16.hpp"
#include <cstdint>
#include <iostream>
using RawrXD::REAP::Float32BitsToFloat16;
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
    std::cout<<"REAP_F16_RESULT="<<(fails?"FAIL":"PASS")
             <<" failures="<<fails<<"\n";
    return fails?1:0;
}
