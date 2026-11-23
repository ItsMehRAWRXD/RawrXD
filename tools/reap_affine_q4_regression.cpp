#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
static void WriteHalf(std::ofstream& out,float f) {
    uint32_t bits=0;std::memcpy(&bits,&f,4);
    const uint16_t h=Float32BitsToFloat16(bits);
    out.put(static_cast<char>(h));out.put(static_cast<char>(h>>8));
}
int main() {
    int failures=0;
    for(uint32_t type : {3u,7u}) {
        const char* source="reap_affine_source.gguf";
        const char* target="reap_affine_target.gguf";
        {
            std::ofstream out(source,std::ios::binary);
            WriteU32(out,0x46554747);WriteU32(out,3);
            WriteU64(out,1);WriteU64(out,0);
            WriteName(out,"weight");WriteU32(out,2);
            WriteU64(out,32);WriteU64(out,1);
            WriteU32(out,type);WriteU64(out,0);PadTo(out,32);
            WriteHalf(out,1.0f);WriteHalf(out,-8.0f);
            if(type==7) {
                for(unsigned i=0;i<4;++i)out.put(static_cast<char>(0));
            }
            for(unsigned i=0;i<16;++i) {
                const unsigned low=i%16;
                const unsigned high=(i+16)%16;
                out.put(static_cast<char>(low|(high<<4)));
            }
        }
        const bool success=RepackGGUF(source,target,UINT64_MAX,false,false,true)==RepackError::None;
        bool correct=success;
        if(success) {
            std::ifstream in(target,std::ios::binary);
            uint32_t u=0,nd=0,dtype=0;uint64_t n=0,offset=0;
            std::string name;
            ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
            ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU64(in,n);
            ReadU32(in,dtype);ReadU64(in,offset);
            const uint64_t start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
            in.seekg(static_cast<std::streamoff>(start));
            unsigned char bytes[18]={};in.read(reinterpret_cast<char*>(bytes),18);
            const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
            const uint32_t bits=Float16ToFloat32Bits(h);
            float d=0;std::memcpy(&d,&bits,4);
            correct &= in.good()&&dtype==2&&std::isfinite(d)&&d!=0;
            for(unsigned i=0;i<32;++i) {
                const unsigned code=i<16?(bytes[2+i]&15):(bytes[2+i-16]>>4);
                const float reconstructed=(static_cast<int>(code)-8)*d;
                correct &= std::abs(reconstructed-(static_cast<int>(i%16)-8))<=1.1f;
            }
        }
        if(!correct){std::cerr<<"FAIL affine source type="<<type<<"\n";++failures;}
        std::remove(source);std::remove(target);
    }
    std::cout<<"REAP_AFFINE_Q4="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
