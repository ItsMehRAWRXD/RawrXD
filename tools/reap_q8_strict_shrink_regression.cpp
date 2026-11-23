#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q8_no_expansion_src.gguf";
    const char* dst="reap_q8_no_expansion_dst.gguf";
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,2);WriteU64(out,0);
        WriteName(out,"blk.0.attn_q.weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,2);
        WriteU32(out,15);WriteU64(out,0);
        WriteName(out,"blk.0.attn_k.weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,2);
        WriteU32(out,8);WriteU64(out,320);
        PadTo(out,32);
        for(unsigned i=0;i<292;++i)out.put(0);
        for(unsigned i=292;i<320;++i)out.put(0);
        for(unsigned i=0;i<68;++i)out.put(0);
    }
    const bool repacked=RepackGGUF(src,dst,UINT64_MAX,false,true)==RepackError::None;
    bool ok=repacked;
    if(ok) {
        std::ifstream in(dst,std::ios::binary);
        uint32_t u=0,nd=0,types[2]={};uint64_t n=0,offsets[2]={};
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        for(unsigned i=0;i<2;++i) {
            ReadName(in,name);ReadU32(in,nd);
            for(unsigned j=0;j<nd;++j)ReadU64(in,n);
            ReadU32(in,types[i]);ReadU64(in,offsets[i]);
        }
        ok=types[0]==8 && types[1]==8 &&
           offsets[0]==0 && offsets[1]==288;
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8_STRICT_SHRINK="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
