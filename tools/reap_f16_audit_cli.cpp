#include "../src/reap/NativeF16Accuracy.hpp"
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>

namespace {
bool ParseU64(const char* text,uint64_t& value) {
    if(!text||!*text||*text=='-'||*text=='+')return false;
    errno=0;
    char* end=nullptr;
    const unsigned long long parsed=std::strtoull(text,&end,10);
    if(errno||!end||*end)return false;
    value=static_cast<uint64_t>(parsed);
    return true;
}
}
int main(int argc,char** argv) {
    if(argc!=6) {
        std::cerr<<"Usage: rawrxd-reap-f16-audit SOURCE_F32 OUTPUT_F16"
                    " SOURCE_BYTE_OFFSET OUTPUT_BYTE_OFFSET ELEMENT_COUNT\n";
        return 2;
    }
    uint64_t srcOffset=0,dstOffset=0,elements=0;
    if(!ParseU64(argv[3],srcOffset)||!ParseU64(argv[4],dstOffset)||
       !ParseU64(argv[5],elements)||!elements) {
        std::cerr<<"Invalid offsets or element count\n";
        return 2;
    }
    RawrXD::REAP::F16Accuracy accuracy;
    if(!RawrXD::REAP::AuditF32ToF16(argv[1],argv[2],srcOffset,dstOffset,
                                    elements,accuracy)) {
        std::cerr<<"REAP_F16_AUDIT=FAIL reason=invalid_input_or_payload_mismatch\n";
        return 1;
    }
    std::cout<<std::setprecision(17)
             <<"REAP_F16_AUDIT=PASS elements="<<accuracy.elements
             <<" finite="<<accuracy.finite
             <<" nonfinite="<<accuracy.nonfinite
             <<" overflowed="<<accuracy.overflowed
             <<" max_abs="<<accuracy.max_abs
             <<" max_rel="<<accuracy.max_rel
             <<" rms_abs="<<accuracy.rms_abs<<"\n";
    return 0;
}
