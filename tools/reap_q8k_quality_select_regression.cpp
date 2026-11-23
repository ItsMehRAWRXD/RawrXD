#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q8k_quality_src.bin";
    const char* dst="reap_q8k_quality_dst.bin";
    const float scale=0.1f; // Not exactly representable in FP16.
    uint32_t bits=0;std::memcpy(&bits,&scale,4);
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,bits);
        for(unsigned i=0;i<256;++i)
            out.put(static_cast<char>(static_cast<int>(i)-128));
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
        ok &= in && in.tellg()==std::streamoff(272);
        in.seekg(0);
        double maxError=0;
        bool sawNegative128=false;
        for(unsigned group=0;group<8;++group) {
            unsigned char block[34]={};
            ok &= bool(in.read(reinterpret_cast<char*>(block),34));
            const uint16_t h=uint16_t(block[0])|(uint16_t(block[1])<<8);
            const uint32_t decoded=Float16ToFloat32Bits(h);
            float d=0;std::memcpy(&d,&decoded,4);
            for(unsigned i=0;i<32;++i) {
                const int original=static_cast<int>(group*32+i)-128;
                const int converted=static_cast<int8_t>(block[i+2]);
                if(original==-128 && converted==-128)sawNegative128=true;
                const double error=std::abs(double(original)*scale-double(converted)*d);
                maxError=std::max(maxError,error);
            }
        }
        // Rounding the original scale to FP16 yields at most 128 times
        // the scale-rounding error, substantially below one Q8 step.
        const uint16_t rounded=Float32BitsToFloat16(bits);
        const uint32_t roundedBits=Float16ToFloat32Bits(rounded);
        float roundedScale=0;std::memcpy(&roundedScale,&roundedBits,4);
        ok &= sawNegative128 &&
              maxError<=128.0*std::abs(double(scale)-roundedScale)+1e-6;
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8K_QUALITY_SELECT="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
