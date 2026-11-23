#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_trailing_source.gguf";
    const char* dst="reap_trailing_target.gguf";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.ffn_down.weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,2);WriteU32(out,2);WriteU64(out,0);
        PadTo(out,32);
        for(int block=0;block<2;++block) {
            out.put(0);out.put(static_cast<char>(0x3c));
            for(int i=0;i<16;++i)out.put(static_cast<char>(0x88));
        }
        // The trailing bytes are not tensor data and must not be
        // counted as a successful tensor compression.
        for(int i=0;i<4096;++i)out.put(static_cast<char>(0xa5));
    }
    {
        std::ofstream out(dst,std::ios::binary);
        out<<"PRESERVE";
    }
    if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)
       !=RepackError::Unsupported)++failures;
    {
        std::ifstream in(dst,std::ios::binary);
        std::string value;
        std::getline(in,value);
        if(value!="PRESERVE")++failures;
    }
    if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_TRAILING_NO_SHRINK="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
