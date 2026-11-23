#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_conversion_order_source.gguf";
    const char* dst="reap_conversion_order_target.gguf";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.ffn_up.weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,2);WriteU32(out,0);WriteU64(out,0);
        PadTo(out,32);
        for(int i=0;i<64;++i)WriteU32(out,0x3f800000u);
    }
    // Explicit F32->F16 wins and must not be chained to Q4 or Q8
    // using the mutated tensor type with original F32 payload bytes.
    if(RepackGGUF(src,dst,UINT64_MAX,true,true,true,false,true)!=RepackError::None)
        ++failures;
    else {
        std::ifstream in(dst,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);
        for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        if(!in||type!=1||offset!=0)++failures;
        const auto data=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(data));
        for(int i=0;i<64;++i) {
            unsigned char half[2]={};
            if(!in.read(reinterpret_cast<char*>(half),2) ||
               half[0]!=0 || half[1]!=0x3c) {++failures;break;}
        }
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_CONVERSION_ORDER="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
