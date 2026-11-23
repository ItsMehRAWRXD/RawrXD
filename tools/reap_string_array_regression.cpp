#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
static bool Make(const char* file,bool truncate) {
    std::ofstream out(file,std::ios::binary);
    WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,1);
    WriteName(out,"tokenizer.ggml.tokens");WriteU32(out,9);WriteU32(out,8);
    WriteU64(out,3);
    WriteName(out,"a");WriteName(out,"");WriteName(out,"longer-token");
    if(truncate) { out.close();return true; }
    WriteName(out,"weight");WriteU32(out,1);WriteU64(out,32);
    WriteU32(out,0);WriteU64(out,0);PadTo(out,32);
    for(unsigned i=0;i<32;++i)WriteU32(out,0x3f800000u);
    return static_cast<bool>(out);
}
int main() {
    const char* valid="reap_string_array_source.gguf";
    const char* bad="reap_string_array_truncated.gguf";
    const char* goodOut="reap_string_array_output.gguf";
    const char* badOut="reap_string_array_rejected.gguf";
    int failures=0;
    if(!Make(valid,false)||!Make(bad,true))++failures;
    if(RepackGGUF(valid,goodOut)!=RepackError::None)++failures;
    if(RepackGGUF(bad,badOut)==RepackError::None)++failures;
    std::remove(valid);std::remove(bad);std::remove(goodOut);std::remove(badOut);
    std::cout<<"REAP_STRING_ARRAY="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
