#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main() {
    const char* source="reap_protected_source.gguf";
    const char* target="reap_protected_target.gguf";
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,2);WriteU64(out,0);
        WriteName(out,"blk.0.attn_norm.weight");WriteU32(out,1);
        WriteU64(out,32);WriteU32(out,0);WriteU64(out,0);
        WriteName(out,"blk.0.attn_q.weight");WriteU32(out,1);
        WriteU64(out,32);WriteU32(out,0);WriteU64(out,128);
        PadTo(out,32);
        for(unsigned i=0;i<64;++i) {
            const float v=static_cast<float>(static_cast<int>(i%32)-16);
            uint32_t bits=0;std::memcpy(&bits,&v,4);
            WriteU32(out,bits);
        }
    }
    bool ok=RepackGGUF(source,target,UINT64_MAX,false,false,true)==RepackError::None;
    if(ok) {
        std::ifstream in(target,std::ios::binary);
        uint32_t u=0,nd=0,type1=0,type2=0;
        uint64_t n=0,off1=0,off2=0;
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU32(in,type1);ReadU64(in,off1);
        ok &= name=="blk.0.attn_norm.weight";
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU32(in,type2);ReadU64(in,off2);
        ok &= name=="blk.0.attn_q.weight";
        ok &= type1==0&&type2==2&&off1==0&&off2==128;
    }
    std::remove(source);std::remove(target);
    std::cout<<"REAP_Q4_PROTECTION_INTEGRATION="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
