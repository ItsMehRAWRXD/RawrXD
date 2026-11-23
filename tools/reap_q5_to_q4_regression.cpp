#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    int failures=0;
    const char* source="reap_q5_source.gguf";
    const char* target="reap_q5_target.gguf";
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"weight");WriteU32(out,2);
        WriteU64(out,32);WriteU64(out,1);
        WriteU32(out,6);WriteU64(out,0);
        PadTo(out,32);
        uint32_t bits=0;const float one=1.0f;std::memcpy(&bits,&one,4);
        const uint16_t h=Float32BitsToFloat16(bits);
        out.put(static_cast<char>(h));out.put(static_cast<char>(h>>8));
        unsigned char high[4]={};
        unsigned char low[16]={};
        for(unsigned i=0;i<32;++i) {
            const unsigned code=i; // Q5_0 represents -16 through +15.
            high[i/8]|=static_cast<unsigned char>(((code>>4)&1)<<(i%8));
            if(i<16)low[i]=static_cast<unsigned char>(code&15);
            else low[i-16]|=static_cast<unsigned char>((code&15)<<4);
        }
        out.write(reinterpret_cast<const char*>(high),4);
        out.write(reinterpret_cast<const char*>(low),16);
    }
    if(RepackGGUF(source,target,UINT64_MAX,false,false,true)!=RepackError::None) {
        std::cerr<<"FAIL q5_0_to_q4_0_repack\n";++failures;
    } else {
        std::ifstream in(target,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        const uint64_t start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        unsigned char bytes[18]={};in.read(reinterpret_cast<char*>(bytes),18);
        const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
        const uint32_t bits=Float16ToFloat32Bits(h);
        float d=0;std::memcpy(&d,&bits,4);
        bool ok=in.good()&&type==2&&name=="weight"&&d>0;
        for(unsigned i=0;i<32;++i) {
            const unsigned code=i<16?(bytes[2+i]&15):(bytes[2+i-16]>>4);
            const float value=(static_cast<int>(code)-8)*d;
            ok &= std::abs(value-(static_cast<int>(i)-16))<1.6f;
        }
        if(!ok){std::cerr<<"FAIL q5_0_high_bit_decode_and_reconstruction\n";++failures;}
    }
    std::remove(source);std::remove(target);
    std::cout<<"REAP_Q5_TO_Q4="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
