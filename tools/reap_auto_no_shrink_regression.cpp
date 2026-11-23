#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* source="reap_auto_noshrink_source.gguf";
    const char* target="reap_auto_noshrink_target.gguf";
    int failures=0;
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.ffn_up.weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,2);WriteU32(out,2);WriteU64(out,0);
        PadTo(out,32);
        const unsigned char q4[18]={0,0x3c};
        out.write(reinterpret_cast<const char*>(q4),18);
        out.write(reinterpret_cast<const char*>(q4),18);
    }
    // Auto must not create an equally sized output or silently overwrite
    // a pre-existing destination when no compression is possible.
    {
        std::ofstream out(target,std::ios::binary);
        out<<"SENTINEL";
    }
    if(RepackGGUF(source,target,UINT64_MAX,false,false,false,false,true)
       !=RepackError::Unsupported)++failures;
    {
        std::ifstream in(target,std::ios::binary);
        std::string contents((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
        if(contents!="SENTINEL")++failures;
    }
    std::remove(source);std::remove(target);
    std::cout<<"REAP_AUTO_NO_SHRINK="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
