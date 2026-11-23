#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_replace_source.gguf";
    const char* dst="reap_replace_target.gguf";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_norm.weight");WriteU32(out,1);
        WriteU64(out,32);WriteU32(out,0);WriteU64(out,0);
        PadTo(out,32);
        for(int i=0;i<32;++i)WriteU32(out,0x3f800000u);
    }
    {
        std::ofstream out(dst,std::ios::binary);
        out<<"OLD_DESTINATION";
    }
    if(RepackGGUF(src,dst,UINT64_MAX,true,false,false,false,false)
       !=RepackError::None)++failures;
    {
        std::ifstream in(dst,std::ios::binary);
        uint32_t magic=0,version=0;
        if(!ReadU32(in,magic)||!ReadU32(in,version)||
           magic!=0x46554747u||version!=3)++failures;
    }
    if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_REPLACE_EXISTING="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
