#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* source="reap_auto_vector_source.gguf";
    const char* target="reap_auto_vector_target.gguf";
    int failures=0;
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.ffn_up.weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,1);WriteU32(out,0);WriteU64(out,0);
        PadTo(out,32);
        for(unsigned i=0;i<32;++i)WriteU32(out,0x3f800000u);
    }
    if(RepackGGUF(source,target,UINT64_MAX,false,false,false,false,true)!=RepackError::None) {
        ++failures;
    } else {
        std::ifstream in(target,std::ios::binary);
        uint32_t v=0,nd=0,type=0;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,v);ReadU32(in,v);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);
        for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        if(!in||type!=0||offset!=0)++failures;
    }
    std::remove(source);std::remove(target);
    std::cout<<"REAP_AUTO_SINGLETON="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
