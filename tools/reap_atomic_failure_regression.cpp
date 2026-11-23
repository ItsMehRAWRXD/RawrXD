#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_atomic_failure_src.gguf";
    const char* dst="reap_atomic_failure_dst.gguf";
    const char* stage="reap_atomic_failure_dst.gguf.reap-part";
    std::remove(src);std::remove(dst);std::remove(stage);
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_q.weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,2);
        WriteU32(out,15);WriteU64(out,0);
        PadTo(out,32);
        // Two valid-size Q8_K blocks with overflowing FP32 scales.
        for(unsigned block=0;block<2;++block) {
            WriteU32(out,0x501502f9); // 1e10f: cannot fit FP16
            for(unsigned i=0;i<256;++i)out.put(static_cast<char>(127));
            for(unsigned i=0;i<32;++i)out.put(0);
        }
    }
    const std::string sentinel="KEEP_EXISTING_OUTPUT_UNCHANGED";
    {
        std::ofstream out(dst,std::ios::binary);
        out.write(sentinel.data(),static_cast<std::streamsize>(sentinel.size()));
    }
    const RepackError error=RepackGGUF(src,dst,UINT64_MAX,false,true);
    std::ifstream out(dst,std::ios::binary);
    const std::string found((std::istreambuf_iterator<char>(out)),
                            std::istreambuf_iterator<char>());
    std::ifstream leftover(stage,std::ios::binary);
    const bool ok=error!=RepackError::None && found==sentinel && !leftover.good();
    std::remove(src);std::remove(dst);std::remove(stage);
    std::cout<<"REAP_ATOMIC_FAILURE="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
