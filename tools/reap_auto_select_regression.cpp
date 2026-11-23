#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_auto_select_src.gguf";
    const char* dst="reap_auto_select_dst.gguf";
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,3);WriteU64(out,0);
        WriteName(out,"blk.0.attn_norm.weight");WriteU32(out,1);
        WriteU64(out,32);WriteU32(out,0);WriteU64(out,0);
        WriteName(out,"blk.0.attn_q.weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,2);WriteU32(out,0);WriteU64(out,128);
        WriteName(out,"blk.0.attn_k.weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,2);WriteU32(out,12);WriteU64(out,384);
        PadTo(out,32);
        for(unsigned i=0;i<96;++i) {
            const float v=static_cast<float>(static_cast<int>(i%32)-16);
            uint32_t bits=0;std::memcpy(&bits,&v,4);WriteU32(out,bits);
        }
        for(unsigned i=0;i<288;++i)out.put(0);
    }
    bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
    if(ok) {
        std::ifstream in(dst,std::ios::binary);
        uint32_t u=0,nd=0,type[3]={};uint64_t n=0,offset[3]={};
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        for(unsigned i=0;i<3;++i) {
            ReadName(in,name);ReadU32(in,nd);
            for(unsigned d=0;d<nd;++d)ReadU64(in,n);
            ReadU32(in,type[i]);ReadU64(in,offset[i]);
        }
        ok=type[0]==1&&type[1]==2&&type[2]==12 &&
           offset[0]==0&&offset[1]==64&&offset[2]==128;
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_AUTO_SELECT="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
