#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    int failures=0;
    const char* source="reap_q5k_source.gguf";
    const char* target="reap_q5k_target.gguf";
    {
        std::ofstream out(source,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"weight");WriteU32(out,2);
        WriteU64(out,512);WriteU64(out,1);
        WriteU32(out,13);WriteU64(out,0);PadTo(out,32);
        for(unsigned superblock=0;superblock<2;++superblock) {
        const float one=1.0f;uint32_t bits=0;std::memcpy(&bits,&one,4);
        const uint16_t h=Float32BitsToFloat16(bits);
        out.put(static_cast<char>(h));out.put(static_cast<char>(h>>8));
        out.put(static_cast<char>(h));out.put(static_cast<char>(h>>8)); // dmin=1
        unsigned char scales[12]={};
        for(unsigned i=0;i<4;++i){scales[i]=1;scales[i+4]=1;}
        for(unsigned i=8;i<12;++i)scales[i]=0x11; // scale=1, minimum=1
        out.write(reinterpret_cast<const char*>(scales),12);
        unsigned char qh[32]={},qs[128]={};
        for(unsigned group=0;group<8;++group) {
            for(unsigned i=0;i<32;++i) {
                const unsigned code=i;
                qh[i]|=static_cast<unsigned char>(((code>>4)&1)<<group);
                const unsigned index=(group/2)*32+i;
                qs[index]|=static_cast<unsigned char>((code&15)<<(group%2?4:0));
            }
        }
        out.write(reinterpret_cast<const char*>(qh),32);
        out.write(reinterpret_cast<const char*>(qs),128);
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
        correct &= type==2&&offset==0;
        for(unsigned block=0;block<16;++block) {
            unsigned char bytes[18]={};
            in.read(reinterpret_cast<char*>(bytes),18);
            const uint16_t half=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
            const uint32_t bits=Float16ToFloat32Bits(half);
            float d=0;std::memcpy(&d,&bits,4);
            correct &= in.good()&&std::isfinite(d)&&d<0;
            for(unsigned i=0;i<32;++i) {
                const unsigned code=i<16?(bytes[2+i]&15):(bytes[2+i-16]>>4);
                const float recovered=(static_cast<int>(code)-8)*d;
                correct &= std::abs(recovered-static_cast<float>(static_cast<int>(i)-1))<2.1f;
            }
        }
    }
    if(!correct){std::cerr<<"FAIL q5_k_to_q4_0\n";++failures;}
    std::remove(source);std::remove(target);
    std::cout<<"REAP_Q5K_TO_Q4="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
    return failures?1:0;
}
