#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q8_no_expansion_src.gguf";
    const char* dst="reap_q8_no_expansion_dst.gguf";
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,2);WriteU64(out,0);
        WriteName(out,"blk.0.attn_q.weight");WriteU32(out,2);
        WriteU64(out,256);WriteU64(out,2);
        WriteU32(out,15);WriteU64(out,0);
        WriteName(out,"blk.0.attn_k.weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,2);
        WriteU32(out,8);WriteU64(out,320);
        PadTo(out,32);
        // Q8_K: FP32 scale, 256 signed quantized values, 16 int16 sums.
        // Nonzero data catches accidental header/scale/offset confusion.
        WriteU32(out,0x3f800000); // d = 1.0
        for(unsigned i=0;i<256;++i)
            out.put(static_cast<char>(static_cast<int>(i%32)-16));
        for(unsigned i=0;i<32;++i)out.put(0);
        for(unsigned i=292;i<320;++i)out.put(0);
        for(unsigned i=0;i<68;++i)out.put(0);
    }
    const bool repacked=RepackGGUF(src,dst,UINT64_MAX,false,true)==RepackError::None;
    bool ok=repacked;
    if(ok) {
        std::ifstream in(dst,std::ios::binary);
        uint32_t u=0,nd=0,types[2]={};uint64_t n=0,offsets[2]={};
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        for(unsigned i=0;i<2;++i) {
            ReadName(in,name);ReadU32(in,nd);
            for(unsigned j=0;j<nd;++j)ReadU64(in,n);
            ReadU32(in,types[i]);ReadU64(in,offsets[i]);
        }
        ok=types[0]==8 && types[1]==8 &&
           offsets[0]==0 && offsets[1]==288;
        const uint64_t start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        unsigned char q8[34]={};
        in.read(reinterpret_cast<char*>(q8),34);
        const uint16_t half=uint16_t(q8[0])|(uint16_t(q8[1])<<8);
        const uint32_t bits=Float16ToFloat32Bits(half);
        float scale=0;std::memcpy(&scale,&bits,4);
        ok &= in.good() && scale>0 && std::isfinite(scale);
        for(unsigned i=0;i<32;++i) {
            const float reconstructed=scale*static_cast<float>(static_cast<int8_t>(q8[i+2]));
            const float expected=static_cast<float>(static_cast<int>(i)-16);
            ok &= std::abs(reconstructed-expected)<0.2f;
        }
    }
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8_STRICT_SHRINK="<<(ok?"PASS":"FAIL")<<"\n";
    return ok?0:1;
}
