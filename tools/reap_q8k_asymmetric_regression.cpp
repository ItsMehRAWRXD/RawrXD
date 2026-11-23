#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q8k_asymmetric_src.bin";
    const char* dst="reap_q8k_asymmetric_dst.bin";
    const float scale=0.10001f;
    uint32_t bits=0;std::memcpy(&bits,&scale,4);
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,bits);
        // Negative-only blocks exercise the -128 signed endpoint.
        for(unsigned i=0;i<256;++i)
            out.put(static_cast<char>(i%32==0?-128:(i%32==1?-127:0)));
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
        const uint16_t directHalf=Float32BitsToFloat16(bits);
        const uint32_t directBits=Float16ToFloat32Bits(directHalf);
        float directScale=0;std::memcpy(&directScale,&directBits,4);
        for(unsigned group=0;group<8;++group) {
            unsigned char block[34]={};
            ok &= bool(in.read(reinterpret_cast<char*>(block),34));
            const uint16_t h=uint16_t(block[0])|(uint16_t(block[1])<<8);
            const uint32_t dbits=Float16ToFloat32Bits(h);
            float d=0;std::memcpy(&d,&dbits,4);
            ok &= std::isfinite(d);
            double chosenError=0,directError=0;
            for(unsigned i=0;i<32;++i) {
                const int original=i==0?-128:(i==1?-127:0);
                const int code=static_cast<int8_t>(block[i+2]);
                chosenError=std::max(chosenError,std::abs(double(original)*scale-double(code)*d));
                directError=std::max(directError,std::abs(double(original)*(scale-directScale)));
            }
            ok &= chosenError<=directError+1e-6;
        }
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8K_ASYMMETRIC="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
