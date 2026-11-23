#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    int failures=0;
    const char* source="reap_q8k_q8_source.gguf";
    const char* target="reap_q8k_q8_target.gguf";
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,1);
        WriteU32(out,15);WriteU64(out,0);PadTo(out,32);
        uint32_t bits=0;const float scale=0.5f;std::memcpy(&bits,&scale,4);
        WriteU32(out,bits);
        for(unsigned i=0;i<256;++i)out.put(static_cast<char>(static_cast<int>(i%32)-16));
        for(unsigned i=0;i<32;++i)out.put(0);
    }
    bool correct=RepackGGUF(source,target,UINT64_MAX,false,true)==RepackError::None;
    if(correct) {
        std::ifstream in(target,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        const uint64_t start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        correct &= type==8&&offset==0;
        for(unsigned block=0;block<8;++block) {
            unsigned char bytes[34]={};
            in.read(reinterpret_cast<char*>(bytes),34);
            const uint16_t half=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
            const uint32_t bits=Float16ToFloat32Bits(half);
            float d=0;std::memcpy(&d,&bits,4);
            correct &= in.good()&&std::isfinite(d)&&d>0;
            for(unsigned i=0;i<32;++i) {
                const float recovered=static_cast<float>(static_cast<int8_t>(bytes[2+i]))*d;
                const float expected=0.5f*static_cast<float>(static_cast<int>(i)-16);
                correct &= std::abs(recovered-expected)<0.2f;
            }
        }
    }
    if(!correct){std::cerr<<"FAIL q8_k_to_q8_0\n";++failures;}
    std::remove(source);std::remove(target);
    std::cout<<"REAP_Q8K_TO_Q8="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
