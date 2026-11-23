#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_auto_q6_sensitive_source.gguf";
    const char* dst="reap_auto_q6_sensitive_target.gguf";
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_norm.weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,2);
        WriteU32(out,14);WriteU64(out,0);
        PadTo(out,32);
        for(unsigned i=0;i<420;++i)out.put(0);
    }
    bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
    if(ok) {
        std::ifstream in(dst,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);
        for(unsigned i=0;i<nd;++i)ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        ok=bool(in)&&type==6&&offset==0;
        std::ifstream before(src,std::ios::binary|std::ios::ate);
        std::ifstream after(dst,std::ios::binary|std::ios::ate);
        ok &= bool(before)&&bool(after)&&after.tellg()<before.tellg();
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_AUTO_Q6_SENSITIVE="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
