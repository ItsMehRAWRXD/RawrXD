#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    int failures=0;
    const char* source="reap_q81_q80_source.gguf";
    const char* target="reap_q81_q80_target.gguf";
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_q.weight");WriteU32(out,1);
        WriteU64(out,64);WriteU32(out,9);WriteU64(out,0);
        PadTo(out,32);
        for(unsigned block=0;block<2;++block) {
            const float scale=block?0.25f:0.5f;
            uint32_t bits=0;std::memcpy(&bits,&scale,4);
            WriteU16(out,Float32BitsToFloat16(bits));
            WriteU16(out,0x7e00u); // must NOT affect decoding
            for(unsigned i=0;i<32;++i)
                out.put(static_cast<char>(static_cast<int>(i)-16));
        }
    }
    bool ok=RepackGGUF(source,target,UINT64_MAX,false,true)==RepackError::None;
    if(ok) {
        std::ifstream in(target,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        ok &= type==8&&offset==0;
        const uint64_t start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        for(unsigned block=0;block<2;++block) {
            unsigned char bytes[34]={};
            in.read(reinterpret_cast<char*>(bytes),34);
            const uint16_t half=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
            const uint32_t bits=Float16ToFloat32Bits(half);
            float d=0;std::memcpy(&d,&bits,4);
            ok &= in.good()&&std::isfinite(d)&&d>0;
            for(unsigned i=0;i<32;++i) {
                const float value=static_cast<float>(static_cast<int8_t>(bytes[2+i]))*d;
                const float expected=(block?0.25f:0.5f)*static_cast<float>(static_cast<int>(i)-16);
                ok &= std::abs(value-expected)<0.2f;
            }
        }
    }
    std::remove(source);std::remove(target);
    if(!ok)++failures;
    std::cout<<"REAP_Q81_TO_Q80="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
