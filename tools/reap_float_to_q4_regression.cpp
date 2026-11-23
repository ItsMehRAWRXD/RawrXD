#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    int failures=0;
    for(uint32_t sourceType : {0u,1u}) {
        const char* source="reap_float_q4_source.gguf";
        const char* target="reap_float_q4_target.gguf";
        {
            std::ofstream out(source,std::ios::binary);
            WriteU32(out,0x46554747);WriteU32(out,3);
            WriteU64(out,1);WriteU64(out,0);
            WriteName(out,"weight");WriteU32(out,2);
            WriteU64(out,32);WriteU64(out,1);
            WriteU32(out,sourceType);WriteU64(out,0);PadTo(out,32);
            for(int i=0;i<32;++i) {
                float value=static_cast<float>(i-16);
                uint32_t bits=0;std::memcpy(&bits,&value,4);
                if(sourceType==0)WriteU32(out,bits);
                else {
                    const uint16_t h=Float32BitsToFloat16(bits);
                    out.put(static_cast<char>(h));out.put(static_cast<char>(h>>8));
                }
            }
        }
        bool correct=RepackGGUF(source,target,UINT64_MAX,false,false,true)==RepackError::None;
        if(correct) {
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
            float scale=0;std::memcpy(&scale,&bits,4);
            correct &= in.good()&&type==2&&std::isfinite(scale)&&scale>0;
            for(unsigned i=0;i<32;++i) {
                const unsigned q=i<16?(bytes[2+i]&15):(bytes[2+i-16]>>4);
                const float recovered=(static_cast<int>(q)-8)*scale;
                correct &= std::abs(recovered-(static_cast<int>(i)-16))<1.6f;
            }
        }
        if(!correct){std::cerr<<"FAIL float_to_q4 source_type="<<sourceType<<"\n";++failures;}
        std::remove(source);std::remove(target);
    }
    std::cout<<"REAP_FLOAT_TO_Q4="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
