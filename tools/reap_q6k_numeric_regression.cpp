#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q6k_numeric_source.gguf";
    const char* dst="reap_q6k_numeric_target.gguf";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.ffn_up.weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,2);WriteU32(out,14);WriteU64(out,0);
        PadTo(out,32);
        for(int block=0;block<2;++block) {
            // GGML Q6_K: 128 low-nibble bytes, 64 high-bit bytes,
            // 16 signed scales and one FP16 superblock scale.
            for(int i=0;i<128;++i)out.put(static_cast<char>(0x88));
            for(int i=0;i<64;++i)out.put(static_cast<char>(0xaa));
            for(int i=0;i<16;++i)out.put(static_cast<char>(1));
            out.put(0);out.put(static_cast<char>(0x3c)); // FP16 1.0
        }
    }
    // Every Q6_K code is 0x28 - 32 = 8; Q4_0 reconstruction
    // must stay close to 8 rather than just produce a smaller file.
    if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)!=RepackError::None)
        ++failures;
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
                const unsigned q=i<16?(packed&15):(packed>>4);
                const float value=scale*(static_cast<int>(q)-8);
                if(!std::isfinite(value)||std::abs(value-8.0f)>1.0f)++failures;
            }
        }
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q6K_NUMERIC="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
