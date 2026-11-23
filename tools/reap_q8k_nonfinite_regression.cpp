#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q8k_nonfinite_src.bin";
    const char* dst="reap_q8k_nonfinite_dst.bin";
    bool ok=true;
    for(const uint32_t bad : {uint32_t(0x7f800000),uint32_t(0xff800000),uint32_t(0x7fc00000)}) {
        {
            std::ofstream out(src,std::ios::binary|std::ios::trunc);
            WriteU32(out,bad);
            for(unsigned i=0;i<256;++i)out.put(static_cast<char>(i));
            for(unsigned i=0;i<32;++i)out.put(0);
        }
        std::ifstream in(src,std::ios::binary);
        std::ofstream out(dst,std::ios::binary|std::ios::trunc);
        ok &= !ConvertQ8KToQ8_0(in,out,0,292);
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8K_NONFINITE_REJECT="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
