#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    int fails=0;
    auto check=[&](bool ok,const char* label){
        std::cout<<(ok?"PASS ":"FAIL ")<<label<<"\n";
        if(!ok)++fails;
    };
    const char* source="reap_q4_source.gguf";
    const char* target="reap_q4_target.gguf";
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,1);
        WriteU32(out,8);WriteU64(out,0);
        PadTo(out,32);
        uint32_t bits=0;const float scale=1.0f;
        std::memcpy(&bits,&scale,4);
        const uint16_t h=Float32BitsToFloat16(bits);
        out.put(static_cast<char>(h));out.put(static_cast<char>(h>>8));
        for(int i=0;i<32;++i)out.put(static_cast<char>(i-16));
    }
    check(RepackGGUF(source,target,UINT64_MAX,false,false,true)==RepackError::None,
          "q8_0_to_q4_0_repack");
    {
        std::ifstream in(target,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        const uint64_t start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        unsigned char bytes[18]={};
        in.read(reinterpret_cast<char*>(bytes),18);
        const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
        const uint32_t bits=Float16ToFloat32Bits(h);
        float scale=0;std::memcpy(&scale,&bits,4);
        bool accurate=in.good()&&name=="weight"&&type==2&&offset==0&&scale>0;
        for(unsigned i=0;i<32;++i) {
            const unsigned code=i<16?(bytes[2+i]&15):(bytes[2+i-16]>>4);
            const float reconstructed=(static_cast<int>(code)-8)*scale;
            accurate &= std::abs(reconstructed-static_cast<float>(static_cast<int>(i)-16))<=1.5f;
        }
        check(accurate,"q4_0_directory_and_decoded_weights");
    }
    check(RepackGGUF(source,target,UINT64_MAX,true,false,true)==RepackError::Unsupported,
          "q4_0_modes_exclusive");
    std::remove(source);std::remove(target);
    std::cout<<"REAP_Q4_0_RESULT="<<(fails?"FAIL":"PASS")<<" failures="<<fails<<"\n";
    return fails?1:0;
}
