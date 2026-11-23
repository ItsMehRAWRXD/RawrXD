#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_auto_q81_matrix_src.gguf";
    const char* dst="reap_auto_q81_matrix_dst.gguf";
    std::remove(src);std::remove(dst);
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_q.weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,2);
        WriteU32(out,9);WriteU64(out,0);
        PadTo(out,32);
        for(unsigned block=0;block<16;++block) {
            WriteU16(out,0x3800); // FP16 0.5
            WriteU16(out,0x0000); // Q8_1 auxiliary sum
            for(unsigned i=0;i<32;++i)
                out.put(static_cast<char>(static_cast<int>((i+block)%256)-128));
        }
    }
    bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
    if(ok) {
        std::ifstream in(dst,std::ios::binary|std::ios::ate);
        const auto size=in.tellg();
        ok=bool(in) && size>0;
        in.seekg(0);
        uint32_t magic=0,version=0,nd=0,type=0;
        uint64_t tensors=0,kv=0,d0=0,d1=0,offset=0;
        std::string name;
        ok &= ReadU32(in,magic)&&ReadU32(in,version)&&ReadU64(in,tensors)&&
              ReadU64(in,kv)&&ReadName(in,name)&&ReadU32(in,nd)&&
              ReadU64(in,d0)&&ReadU64(in,d1)&&ReadU32(in,type)&&ReadU64(in,offset);
        ok &= magic==0x46554747 && version==3 && tensors==1 && kv==0 &&
              nd==2 && d0==256 && d1==2 && type==8 && offset==0;
        if(ok) {
            const auto directoryEnd=in.tellg();
            const uint64_t dataStart=(static_cast<uint64_t>(directoryEnd)+31u)&~uint64_t(31u);
            ok &= static_cast<uint64_t>(size)==dataStart+16u*34u;
            in.seekg(static_cast<std::streamoff>(dataStart));
            for(unsigned block=0;block<16;++block) {
                unsigned char bytes[34]={};
                ok &= bool(in.read(reinterpret_cast<char*>(bytes),34));
                ok &= bytes[0]==0x00 && bytes[1]==0x38;
                for(unsigned i=0;i<32;++i)
                    ok &= static_cast<int8_t>(bytes[i+2])==
                          static_cast<int>((i+block)%256)-128;
            }
        }
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_AUTO_Q81_MATRIX="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
