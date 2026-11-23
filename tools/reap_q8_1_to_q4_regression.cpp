#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
static void WriteFloat(std::ofstream& out,float value) {
    uint32_t bits=0;std::memcpy(&bits,&value,4);WriteU32(out,bits);
}
int main() {
    int failures=0;
    const char* source="reap_q8_1_source.gguf";
    const char* target="reap_q8_1_target.gguf";
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,1);
        WriteU32(out,9);WriteU64(out,0);PadTo(out,32);
        WriteFloat(out,1.0f);
        WriteFloat(out,-16.0f); // Q8_1 sum metadata, not the scale
        for(int i=0;i<32;++i)out.put(static_cast<char>(i-16));\n        // 40-byte block: 8 bytes of FP32 metadata plus 32 signed weights.
    }
    const bool success=RepackGGUF(source,target,UINT64_MAX,false,false,true)==RepackError::None;
    if(!success){std::cerr<<"FAIL q8_1_conversion\n";++failures;}
    else {
        std::ifstream in(target,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        const uint64_t start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        unsigned char bytes[18]={};in.read(reinterpret_cast<char*>(bytes),18);
        const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
        const uint32_t bits=Float16ToFloat32Bits(h);
        float scale=0;std::memcpy(&scale,&bits,4);
        bool accurate=in.good()&&type==2&&scale>0;
        for(unsigned i=0;i<32;++i) {
            const unsigned code=i<16?(bytes[2+i]&15):(bytes[2+i-16]>>4);
            const float recovered=(static_cast<int>(code)-8)*scale;
            accurate &= std::abs(recovered-(static_cast<int>(i)-16))<1.6f;
        }
        if(!accurate){std::cerr<<"FAIL q8_1_decoded_values\n";++failures;}
    }
    std::remove(source);std::remove(target);
    std::cout<<"REAP_Q8_1_TO_Q4_0="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
