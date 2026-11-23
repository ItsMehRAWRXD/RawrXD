#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <vector>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_auto_source.gguf";
    const char* dst="reap_auto_target.gguf";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747); WriteU32(out,3); WriteU64(out,3); WriteU64(out,0);
        // F32 normalization stays higher precision (F16); ordinary F32 becomes Q4_0.
        WriteName(out,"blk.0.attn_norm.weight"); WriteU32(out,1);
        WriteU64(out,32); WriteU32(out,0); WriteU64(out,0);
        WriteName(out,"blk.0.ffn_up.weight"); WriteU32(out,2);
        WriteU64(out,32); WriteU64(out,2); WriteU32(out,0); WriteU64(out,128);
        // Existing Q4_0 must not be requantized or inflated.
        WriteName(out,"blk.0.ffn_down.weight"); WriteU32(out,2);
        WriteU64(out,32); WriteU64(out,2); WriteU32(out,2); WriteU64(out,384);
        PadTo(out,32);
        for(int i=0;i<96;++i) {uint32_t bits=0x3f800000u;WriteU32(out,bits);}
        unsigned char q4[18]={};q4[0]=0; q4[1]=0x3c;
        out.write(reinterpret_cast<const char*>(q4),18);
        out.write(reinterpret_cast<const char*>(q4),18);
    }
    if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)!=RepackError::None) {
        std::cerr<<"FAIL auto repack\n";++failures;
    } else {
        std::ifstream in(dst,std::ios::binary);
        uint32_t v=0,nd=0,type=0;uint64_t n=0,offset=0;
        ReadU32(in,v);ReadU32(in,v);ReadU64(in,n);ReadU64(in,n);
        const uint32_t expected[]={1,2,2};
        const uint64_t expectedOffsets[]={0,64,128};
        for(unsigned i=0;i<3;++i) {
            std::string name;ReadName(in,name);ReadU32(in,nd);
            for(uint32_t j=0;j<nd;++j)ReadU64(in,n);
            ReadU32(in,type);ReadU64(in,offset);
            if(type!=expected[i]||offset!=expectedOffsets[i])++failures;
        }
        if(!in)++failures;
        std::ifstream source(src,std::ios::binary|std::ios::ate);
        std::ifstream target(dst,std::ios::binary|std::ios::ate);
        if(!source||!target||target.tellg()>=source.tellg())++failures;
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_AUTO="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
