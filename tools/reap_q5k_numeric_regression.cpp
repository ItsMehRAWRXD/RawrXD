#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q5k_numeric_source.gguf";
    const char* dst="reap_q5k_numeric_target.gguf";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.ffn_up.weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,2);WriteU32(out,13);WriteU64(out,0);
        PadTo(out,32);
        for(int block=0;block<2;++block) {
            // Q5_K: d=1, dmin=0, 8 six-bit scales=1,
            // 8 six-bit minima=0, qh=0, packed qs=8.
            WriteU16(out,0x3c00u);WriteU16(out,0u);
            for(int i=0;i<12;++i)out.put(static_cast<char>(i<8?1:0));
            for(int i=0;i<32;++i)out.put(0);
            for(int i=0;i<128;++i)out.put(static_cast<char>(0x88));
        }
    }
    if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)
       !=RepackError::None)++failures;
    else {
        std::ifstream in(dst,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);
        for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        if(!in||type!=2||offset!=0)++failures;
        const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        for(int block=0;block<16;++block) {
            unsigned char bytes[18]={};
            if(!in.read(reinterpret_cast<char*>(bytes),18)) {++failures;break;}
            const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
            const uint32_t bits=Float16ToFloat32Bits(h);
            float scale=0;std::memcpy(&scale,&bits,4);
            for(int i=0;i<32;++i) {
                const unsigned char packed=bytes[2+i%16];
                const int q=i<16?(packed&15):(packed>>4);
                const float reconstructed=scale*(q-8);
                if(!std::isfinite(reconstructed)||std::abs(reconstructed-8.0f)>1.0f)
                    ++failures;
            }
        }
        std::ifstream a(src,std::ios::binary|std::ios::ate);
        std::ifstream b(dst,std::ios::binary|std::ios::ate);
        if(!a||!b||b.tellg()>=a.tellg())++failures;
    }
    if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q5K_NUMERIC="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
