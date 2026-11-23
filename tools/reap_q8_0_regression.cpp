#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    int fails=0;
    auto check=[&](bool ok,const char* label) {
        std::cout<<(ok?"PASS ":"FAIL ")<<label<<"\n";
        if(!ok)++fails;
    };
    const char* src="reap_q8_source.gguf";
    const char* dst="reap_q8_output.gguf";
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,1);
        WriteU32(out,0);WriteU64(out,0);
        PadTo(out,32);
        for(int i=0;i<32;++i) {
            float value=static_cast<float>(i-16);
            uint32_t bits=0;std::memcpy(&bits,&value,4);
            WriteU32(out,bits);
        }
    }
    check(RepackGGUF(src,dst,UINT64_MAX,false,true)==RepackError::None,
          "q8_0_repack_success");
    {
        std::ifstream in(dst,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        check(name=="weight"&&nd==2&&type==8&&offset==0,
              "q8_0_tensor_directory");
        const uint64_t start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        unsigned char bytes[34]={};
        in.read(reinterpret_cast<char*>(bytes),34);
        const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
        const uint32_t scaleBits=Float16ToFloat32Bits(h);
        float scale=0;std::memcpy(&scale,&scaleBits,4);
        bool accurate=in.good()&&scale>0;
        for(int i=0;i<32;++i) {
            const int8_t q=static_cast<int8_t>(bytes[i+2]);
            const float recovered=q*scale;
            accurate &= std::abs(recovered-static_cast<float>(i-16))<0.15f;
        }
        check(accurate,"q8_0_payload_decode_within_error");
    }
    check(RepackGGUF(src,dst,UINT64_MAX,true,true)==RepackError::Unsupported,
          "mutually_exclusive_quantization_modes");
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q8_0_RESULT="<<(fails?"FAIL":"PASS")<<" failures="<<fails<<"\n";
    return fails?1:0;
}
