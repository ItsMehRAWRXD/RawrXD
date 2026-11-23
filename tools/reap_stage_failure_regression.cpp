#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_stage_failure_source.gguf";
    const char* dst="reap_stage_failure_target.gguf";
    const std::string stage=std::string(dst)+".reap-part";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_norm.weight");WriteU32(out,1);
        WriteU64(out,32);WriteU32(out,0);WriteU64(out,0);
        PadTo(out,32);
        for(int i=0;i<32;++i)WriteU32(out,i==9?0x7fc00000u:0x3f800000u);
    }
    {
        std::ofstream out(dst,std::ios::binary);
        out<<"PRESERVE_EXISTING_OUTPUT";
    }
    // NaN is rejected by the F32->F16 quantizer after output staging
    // begins; the existing destination must survive unchanged.
    if(RepackGGUF(src,dst,UINT64_MAX,true,false,false,false,false)
       !=RepackError::Output)++failures;
    {
        std::ifstream in(dst,std::ios::binary);
        std::string contents((std::istreambuf_iterator<char>(in)),
                              std::istreambuf_iterator<char>());
        if(contents!="PRESERVE_EXISTING_OUTPUT")++failures;
    }
    if(std::filesystem::exists(stage))++failures;
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_STAGE_FAILURE="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
