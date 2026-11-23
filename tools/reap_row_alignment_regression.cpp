#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
static void Make(const char* path,uint32_t type) {
    std::ofstream out(path,std::ios::binary);
    WriteU32(out,0x46554747);WriteU32(out,3);
    WriteU64(out,1);WriteU64(out,0);
    WriteName(out,"matrix");WriteU32(out,2);
    WriteU64(out,16);WriteU64(out,2);
    WriteU32(out,type);WriteU64(out,0);
    PadTo(out,32);
    const unsigned bytes=type==0?128:34;
    for(unsigned i=0;i<bytes;++i)out.put('\0');
}
int main() {
    int failures=0;
    const char* source="reap_row_source.gguf";
    const char* output="reap_row_output.gguf";
    Make(source,0);
    if(RepackGGUF(source,output,UINT64_MAX,false,true)!=RepackError::None) {
        std::cerr<<"FAIL unaligned_f32_row_fallback\n";++failures;
    } else {
        std::ifstream in(output,std::ios::binary);
        uint32_t v=0,nd=0,type=99;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,v);ReadU32(in,v);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        if(type!=0){std::cerr<<"FAIL converted_across_row_boundary\n";++failures;}
    }
    std::remove(source);std::remove(output);
    Make(source,8);
    if(RepackGGUF(source,output,UINT64_MAX,false,false,true)!=RepackError::Unsupported) {
        std::cerr<<"FAIL malformed_quantized_row_accepted\n";++failures;
    }
    std::remove(source);std::remove(output);
    std::cout<<"REAP_ROW_ALIGNMENT="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
