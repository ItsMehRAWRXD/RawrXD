#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q8k_zero_huge_scale_src.bin";
    const char* dst="reap_q8k_zero_huge_scale_dst.bin";
    const float scale=1.0e30f;
    uint32_t bits=0;std::memcpy(&bits,&scale,4);
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,bits);
        for(unsigned i=0;i<256;++i)out.put(0);
        for(unsigned i=0;i<32;++i)out.put(0);
    }
    bool ok=false;
    {
        std::ifstream in(src,std::ios::binary);
        std::ofstream out(dst,std::ios::binary);
        ok=ConvertQ8KToQ8_0(in,out,0,292);
    }
    if(ok) {
        std::ifstream in(dst,std::ios::binary|std::ios::ate);
        ok=bool(in) && in.tellg()==std::streamoff(272);
        in.seekg(0);
        for(unsigned group=0;group<8;++group) {
            unsigned char block[34]={};
            ok &= bool(in.read(reinterpret_cast<char*>(block),34));
            const uint16_t half=uint16_t(block[0])|(uint16_t(block[1])<<8);
            const uint32_t decoded=Float16ToFloat32Bits(half);
            float d=0;std::memcpy(&d,&decoded,4);
            ok &= std::isfinite(d);
            for(unsigned i=0;i<32;++i)ok &= block[i+2]==0;
        }
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8K_ZERO_HUGE_SCALE="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
