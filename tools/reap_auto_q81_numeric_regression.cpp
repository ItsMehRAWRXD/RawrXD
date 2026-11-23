#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_auto_q81_numeric_source.gguf";
    const char* dst="reap_auto_q81_numeric_target.gguf";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_norm.weight");WriteU32(out,1);
        WriteU64(out,256);WriteU32(out,9);WriteU64(out,0);
        PadTo(out,32);
        for(int block=0;block<8;++block) {
            // GGML Q8_1 is 36 bytes: FP16 d, FP16 d*sum(qs), 32 int8.
            // Sum of [-16, ..., 15] is -16.
            WriteU16(out,0x3c00u); // FP16 1.0
            WriteU16(out,0xcc00u); // FP16 -16.0
            for(int i=0;i<32;++i)out.put(static_cast<char>(i-16));
        }
    }
    if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)!=RepackError::None) {
        ++failures;
    } else {
        std::ifstream in(dst,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);
        for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        if(!in||type!=8||offset!=0)++failures;
        const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        for(int block=0;block<8;++block) {
            unsigned char bytes[34]={};
            if(!in.read(reinterpret_cast<char*>(bytes),34)) {++failures;break;}
            const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
            const uint32_t bits=Float16ToFloat32Bits(h);
            float scale=0;std::memcpy(&scale,&bits,4);
            if(!(scale>0.0f))++failures;
            for(int i=0;i<32;++i) {
                const float reconstructed=static_cast<int8_t>(bytes[2+i])*scale;
                if(!std::isfinite(reconstructed)||
                   std::abs(reconstructed-static_cast<float>(i-16))>0.25f)
                    ++failures;
            }
        }
        std::ifstream a(src,std::ios::binary|std::ios::ate);
        std::ifstream b(dst,std::ios::binary|std::ios::ate);
        if(!a||!b||b.tellg()>=a.tellg())++failures;
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_AUTO_Q81_NUMERIC="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
