#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    bool ok=true;
    const char* src="reap_k_row_layout_src.gguf";
    const char* dst="reap_k_row_layout_dst.gguf";
    struct Layout {uint32_t type;unsigned bytes;};
    const Layout layouts[]={{10,84},{11,110},{12,144},{13,176},{14,210},{15,292}};
    for(const auto& layout:layouts) {
        std::remove(src);std::remove(dst);
        {
            std::ofstream out(src,std::ios::binary);
            WriteU32(out,0x46554747);WriteU32(out,3);
            WriteU64(out,1);WriteU64(out,0);
            WriteName(out,"blk.0.attn_q.weight");WriteU32(out,2);
            // 32 x 8 = 256 elements overall, but each row is only 32.
            WriteU64(out,32);WriteU64(out,8);
            WriteU32(out,layout.type);WriteU64(out,0);
            PadTo(out,32);
            for(unsigned i=0;i<layout.bytes;++i)out.put(0);
        }
        const RepackError error=RepackGGUF(src,dst,UINT64_MAX,
                                            false,false,false,false,true);
        std::ifstream destination(dst,std::ios::binary);
        ok &= error==RepackError::Unsupported && !destination.good();
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_K_ROW_LAYOUT="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
