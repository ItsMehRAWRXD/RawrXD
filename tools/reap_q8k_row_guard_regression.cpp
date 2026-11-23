#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q8k_row_guard_src.gguf";
    const char* dst="reap_q8k_row_guard_dst.gguf";
    std::remove(dst);
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_q.weight");WriteU32(out,2);
        // Total element count is 256, but each logical row is only 32.
        // Q8_K requires 256 elements per row, not just per tensor.
        WriteU64(out,32);WriteU64(out,8);
        WriteU32(out,15);WriteU64(out,0);
        PadTo(out,32);
        for(unsigned i=0;i<292;++i)out.put(0);
    }
    const RepackError result=RepackGGUF(src,dst,UINT64_MAX,false,true);
    std::ifstream target(dst,std::ios::binary);
    const bool ok=result!=RepackError::None && !target.good();
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8K_ROW_GUARD="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
