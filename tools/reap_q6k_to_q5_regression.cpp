#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    int failures=0;
    const char* source="reap_q6k_q5_source.gguf";
    const char* target="reap_q6k_q5_target.gguf";
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"weight");WriteU32(out,2);
        WriteU64(out,512);WriteU64(out,1);
        WriteU32(out,14);WriteU64(out,0);PadTo(out,32);
        for(unsigned superblock=0;superblock<2;++superblock) {
        unsigned char ql[128]={},qh[64]={};
        for(unsigned i=0;i<256;++i) {
            const unsigned half=i/128,quarter=(i%128)/32,lane=i%32;
            const unsigned index=half*64+(quarter%2)*32+lane;
            const unsigned code=static_cast<unsigned>(static_cast<int>(lane)-16+32);
            ql[index]|=static_cast<unsigned char>((code&15)<<(quarter>=2?4:0));
            qh[half*32+lane]|=static_cast<unsigned char>(((code>>4)&3)<<(quarter*2));
        }
        out.write(reinterpret_cast<const char*>(ql),128);
        out.write(reinterpret_cast<const char*>(qh),64);
        for(unsigned i=0;i<16;++i)out.put(1);
        const float one=1.0f;uint32_t bits=0;std::memcpy(&bits,&one,4);
        const uint16_t h=Float32BitsToFloat16(bits);
        out.put(static_cast<char>(h));out.put(static_cast<char>(h>>8));
        }
    }
    bool correct=RepackGGUF(source,target,UINT64_MAX,false,false,false,true)==RepackError::None;
    if(correct) {
        std::ifstream in(target,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;
        std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,n);ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        const uint64_t start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        correct &= type==6&&offset==0;
        for(unsigned block=0;block<16;++block) {
            unsigned char bytes[22]={};
            in.read(reinterpret_cast<char*>(bytes),22);
            const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
            const uint32_t bits=Float16ToFloat32Bits(h);
            float d=0;std::memcpy(&d,&bits,4);
            correct &= in.good()&&std::isfinite(d)&&d>0;
            for(unsigned i=0;i<32;++i) {
                const unsigned j=i%16;
                const unsigned nibble=i<16?(bytes[6+j]&15):(bytes[6+j]>>4);
                const unsigned high=(bytes[2+i/8]>>(i%8))&1;
                const float recovered=(static_cast<int>(nibble|(high<<4))-16)*d;
                correct &= std::abs(recovered-(static_cast<int>(i)-16))<1.1f;
            }
        }
    }
    if(!correct){std::cerr<<"FAIL q6_k_to_q5_0\n";++failures;}
    std::remove(source);std::remove(target);
    std::cout<<"REAP_Q6K_TO_Q5="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
