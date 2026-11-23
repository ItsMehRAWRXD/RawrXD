#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q81_signed_scale_src.bin";
    const char* dst="reap_q81_signed_scale_dst.bin";
    {
        std::ofstream out(src,std::ios::binary);
        const float scales[3]={-0.5f,0.0f,0.25f};
        for(unsigned block=0;block<3;++block) {
            uint32_t bits=0;std::memcpy(&bits,&scales[block],4);
            WriteU32(out,bits);
            WriteU32(out,0x7fc00000u); // ignored Q8_1 sum (NaN)
            for(unsigned i=0;i<32;++i)
                out.put(static_cast<char>(static_cast<int>(i)-16));
        }
    }
    bool ok=false;
    {
        std::ifstream in(src,std::ios::binary);
        std::ofstream out(dst,std::ios::binary);
        ok=ConvertQ8_1ToQ8_0(in,out,0,120);
    }
    if(ok) {
        std::ifstream in(dst,std::ios::binary);
        for(unsigned block=0;block<3;++block) {
            unsigned char bytes[34]={};
            in.read(reinterpret_cast<char*>(bytes),34);
            uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
            uint32_t bits=Float16ToFloat32Bits(h);
            float scale=0;std::memcpy(&scale,&bits,4);
            ok &= bool(in)&&std::isfinite(scale);
            for(unsigned i=0;i<32;++i) {
                const float expected=(block==0?-0.5f:(block==1?0.0f:0.25f))*
                    static_cast<float>(static_cast<int>(i)-16);
                const float actual=scale*static_cast<float>(static_cast<int8_t>(bytes[i+2]));
                ok &= std::abs(actual-expected)<0.15f;
            }
        }
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q81_SIGNED_ZERO_SCALE="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
