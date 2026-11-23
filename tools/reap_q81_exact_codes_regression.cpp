#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q81_exact_src.bin";
    const char* dst="reap_q81_exact_dst.bin";
    const uint32_t scales[3]={0x3f000000u,0xbf800000u,0x00000000u};
    {
        std::ofstream out(src,std::ios::binary);
        for(unsigned block=0;block<3;++block) {
            WriteU16(out,Float32BitsToFloat16(scales[block]));WriteU16(out,0x7e00u);
            for(unsigned i=0;i<32;++i)
                out.put(static_cast<char>(static_cast<int>(i)-128));
        }
    }
    bool ok=false;
    {
        std::ifstream in(src,std::ios::binary);
        std::ofstream out(dst,std::ios::binary);
        ok=ConvertQ8_1ToQ8_0(in,out,0,108);
    }
    if(ok) {
        std::ifstream in(dst,std::ios::binary);
        for(unsigned block=0;block<3;++block) {
            unsigned char bytes[34]={};
            in.read(reinterpret_cast<char*>(bytes),34);
            const uint16_t half=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
            ok &= bool(in) && Float16ToFloat32Bits(half)==scales[block];
            for(unsigned i=0;i<32;++i)
                ok &= bytes[i+2]==static_cast<unsigned char>(static_cast<int>(i)-128);
        }
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q81_EXACT_CODES="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
