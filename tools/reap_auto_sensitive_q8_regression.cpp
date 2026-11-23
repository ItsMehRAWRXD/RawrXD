#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_auto_sensitive_q8_source.gguf";
    const char* dst="reap_auto_sensitive_q8_target.gguf";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.ffn_up.weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,1);WriteU32(out,9);WriteU64(out,0);
        PadTo(out,32);
        for(int block=0;block<1;++block) {
            WriteU32(out,0x3f800000u);WriteU32(out,0xc1800000u);
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
        std::ifstream a(src,std::ios::binary|std::ios::ate);
        std::ifstream b(dst,std::ios::binary|std::ios::ate);
        if(!a||!b||b.tellg()>=a.tellg())++failures;
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_AUTO_VECTOR_Q8="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
