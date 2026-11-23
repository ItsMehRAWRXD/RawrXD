#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
static bool Try(float value) {
    const char* src="reap_f16_guard_src.bin";
    const char* dst="reap_f16_guard_dst.bin";
    uint32_t bits=0;std::memcpy(&bits,&value,4);
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,bits);
    }
    std::ifstream in(src,std::ios::binary);
    std::ofstream out(dst,std::ios::binary);
    const bool ok=ConvertF32RangeToF16(in,out,0,4);
    out.close();in.close();
    std::remove(src);std::remove(dst);
    return ok;
}
int main() {
    int failures=0;
    if(!Try(1.0f))++failures;
    if(!Try(65504.0f))++failures;
    if(Try(65536.0f))++failures;
    if(Try(1.0e-20f))++failures;
    if(Try(std::numeric_limits<float>::infinity()))++failures;
    if(Try(std::numeric_limits<float>::quiet_NaN()))++failures;
    if(!Try(0.0f))++failures;
    std::cout<<"REAP_F16_GUARDS="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
