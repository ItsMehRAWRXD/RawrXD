#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    bool ok=true;
    const char* src="reap_float_q8_signed_src.bin";
    const char* dst="reap_float_q8_signed_dst.bin";
    for(unsigned format=0;format<2;++format) {
        std::remove(src);std::remove(dst);
        {
            std::ofstream out(src,std::ios::binary);
            for(unsigned i=0;i<32;++i) {
                const float v=i==0?-128.0f:(i==1?-64.0f:0.0f);
                if(format==0) {
                    uint32_t bits=0;std::memcpy(&bits,&v,4);WriteU32(out,bits);
                } else {
                    uint32_t bits=0;std::memcpy(&bits,&v,4);WriteU16(out,Float32BitsToFloat16(bits));
                }
            }
        }
        {
            std::ifstream in(src,std::ios::binary);
            std::ofstream out(dst,std::ios::binary);
            ok &= ConvertFloatRangeToQ8_0(in,out,0,format?64:128,format==1);
        }
        std::ifstream in(dst,std::ios::binary|std::ios::ate);
        ok &= bool(in) && in.tellg()==std::streamoff(34);
        in.seekg(0);
        unsigned char bytes[34]={};
        ok &= bool(in.read(reinterpret_cast<char*>(bytes),34));
        const uint16_t half=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
        const uint32_t decoded=Float16ToFloat32Bits(half);
        float d=0;std::memcpy(&d,&decoded,4);
        ok &= std::isfinite(d) && d==1.0f &&
              static_cast<int8_t>(bytes[2])==-128 &&
              static_cast<int8_t>(bytes[3])==-64;
        for(unsigned i=4;i<34;++i)ok &= bytes[i]==0;
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_FLOAT_Q8_SIGNED="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
