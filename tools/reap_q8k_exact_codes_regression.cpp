#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q8k_exact_src.bin";
    const char* dst="reap_q8k_exact_dst.bin";
    const uint32_t scales[3]={0x3f000000u,0xbf800000u,0x00000000u};
    {
        std::ofstream out(src,std::ios::binary);
        for(unsigned block=0;block<3;++block) {
            WriteU32(out,scales[block]);
            for(unsigned i=0;i<256;++i)
                out.put(static_cast<char>(static_cast<int>(i%32)-128));
            for(unsigned i=0;i<32;++i)out.put(0); // Q8_K bsums[16]
        }
    }
    bool ok=false;
    {
        std::ifstream in(src,std::ios::binary);
        std::ofstream out(dst,std::ios::binary);
        ok=ConvertQ8KToQ8_0(in,out,0,876);
    }
    if(ok) {
        std::ifstream in(dst,std::ios::binary);
        for(unsigned block=0;block<3;++block)
            for(unsigned group=0;group<8;++group) {
                unsigned char bytes[34]={};
                in.read(reinterpret_cast<char*>(bytes),34);
                const uint16_t half=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
                ok &= bool(in)&&Float16ToFloat32Bits(half)==scales[block];
                for(unsigned i=0;i<32;++i)
                    ok &= bytes[i+2]==static_cast<unsigned char>(static_cast<int>(i)-128);
            }
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8K_EXACT_CODES="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
