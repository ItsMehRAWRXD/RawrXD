#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_auto_no_shrink_src.gguf";
    const char* dst="reap_auto_no_shrink_dst.gguf";
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_q.weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,2);
        WriteU32(out,12);WriteU64(out,0);
        PadTo(out,32);
        for(unsigned i=0;i<288;++i)out.put(0);
    }
    const RepackError result=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true);
    std::ifstream output(dst,std::ios::binary);
    const bool ok=result==RepackError::Unsupported && !output.good();
    output.close();
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_AUTO_NO_EXPANSION="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
