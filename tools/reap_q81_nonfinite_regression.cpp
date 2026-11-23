#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q81_nonfinite_src.bin";
    const char* dst="reap_q81_nonfinite_dst.bin";
    bool ok=true;
    for(const uint16_t bad : {uint16_t(0x7c00),uint16_t(0xfc00),uint16_t(0x7e00)}) {
        {
            std::ofstream out(src,std::ios::binary|std::ios::trunc);
            WriteU16(out,bad);
            WriteU16(out,0x0000);
            for(unsigned i=0;i<32;++i)out.put(static_cast<char>(i));
        }
        std::ifstream in(src,std::ios::binary);
        std::ofstream out(dst,std::ios::binary|std::ios::trunc);
        ok &= !ConvertQ8_1ToQ8_0(in,out,0,36);
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q81_NONFINITE_REJECT="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
