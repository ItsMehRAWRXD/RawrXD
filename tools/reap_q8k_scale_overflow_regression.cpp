#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q8k_scale_overflow_src.bin";
    const char* dst="reap_q8k_scale_overflow_dst.bin";
    // FP32 scale exceeds FP16 range. Direct-code conversion is invalid,
    // and per-group requantization must also fail closed when its scale
    // overflows. Never emit a Q8_0 block with an infinite scale.
    const float scale=1.0e10f;
    uint32_t bits=0;std::memcpy(&bits,&scale,4);
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,bits);
        for(unsigned i=0;i<256;++i)out.put(static_cast<char>(i%2==0?127:-128));
        for(unsigned i=0;i<32;++i)out.put(0);
    }
    bool ok=false;
    {
        std::ifstream in(src,std::ios::binary);
        std::ofstream out(dst,std::ios::binary|std::ios::trunc);
        ok=!ConvertQ8KToQ8_0(in,out,0,292);
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8K_SCALE_OVERFLOW="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
