#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    // A real-valued block where the lower FP16 scale neighbor has
    // smaller maximum error than either the nearest or upper neighbor.
    const float values[32]={
        -52.790382f,-79.366793f,-20.788351f,-69.005546f,
        -86.696981f,-19.681797f,83.591009f,60.090470f,
        53.032521f,-55.614365f,7.336002f,-44.663471f,
        -65.467094f,-78.763342f,-57.119913f,85.495126f,
        65.784010f,61.330469f,60.089568f,-61.312876f,
        -38.030009f,25.395120f,46.378942f,70.929672f,
        76.010150f,-82.656349f,21.170377f,34.340291f,
        1.190755f,-64.441965f,-5.282422f,-82.130759f};
    const char* src="reap_q8_lower_neighbor_src.bin";
    const char* dst="reap_q8_lower_neighbor_dst.bin";
    {
        std::ofstream out(src,std::ios::binary);
        for(float v:values) {
            uint32_t bits=0;std::memcpy(&bits,&v,4);WriteU32(out,bits);
        }
    }
    bool ok=false;
    {
        std::ifstream in(src,std::ios::binary);
        std::ofstream out(dst,std::ios::binary);
        ok=ConvertFloatRangeToQ8_0(in,out,0,128,false);
    }
    if(ok) {
        std::ifstream in(dst,std::ios::binary|std::ios::ate);
        ok=bool(in)&&in.tellg()==std::streamoff(34);
        in.seekg(0);
        unsigned char bytes[34]={};
        ok &= bool(in.read(reinterpret_cast<char*>(bytes),34));
        const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
        float positive=0,negative=0;
        for(float v:values) {
            positive=std::max(positive,v);
            negative=std::max(negative,-v);
        }
        const float scale=static_cast<float>(
            std::max(double(positive)/127.0,double(negative)/128.0));
        uint32_t bits=0;std::memcpy(&bits,&scale,4);
        const uint16_t nearest=Float32BitsToFloat16(bits);
        // A lower neighbor is strictly better for this block.
        ok &= nearest>0 && h==static_cast<uint16_t>(nearest-1);
        const uint32_t decoded=Float16ToFloat32Bits(h);
        float d=0;std::memcpy(&d,&decoded,4);
        ok &= std::isfinite(d)&&d>0;
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8_LOWER_NEIGHBOR="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
