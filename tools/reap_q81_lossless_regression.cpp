#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main() {
    const char* src="reap_q81_lossless_source.gguf";
    const char* dst="reap_q81_lossless_target.gguf";
    int failures=0;
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"blk.0.attn_norm.weight");WriteU32(out,1);
        WriteU64(out,256);WriteU32(out,9);WriteU64(out,0);
        PadTo(out,32);
        for(int b=0;b<8;++b) {
            WriteU16(out,0x3c00u); // Q8_1 FP16 d = 1
            WriteU16(out,0xcc00u); // Q8_1 FP16 s = -16
            for(int i=0;i<32;++i)out.put(static_cast<char>(i-16));
        }
    }
    if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)
       !=RepackError::None)++failures;
    else {
        std::ifstream in(dst,std::ios::binary);
        uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;std::string name;
        ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
        ReadName(in,name);ReadU32(in,nd);
        for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
        ReadU32(in,type);ReadU64(in,offset);
        if(!in||type!=8||offset!=0)++failures;
        const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(start));
        for(int b=0;b<8;++b) {
            unsigned char bytes[34]={};
            if(!in.read(reinterpret_cast<char*>(bytes),34)) {++failures;break;}
            if(bytes[0]!=0 || bytes[1]!=0x3c)++failures;
            for(int i=0;i<32;++i)
                if(static_cast<int8_t>(bytes[2+i])!=i-16)++failures;
        }
        std::ifstream a(src,std::ios::binary|std::ios::ate);
        std::ifstream b(dst,std::ios::binary|std::ios::ate);
        if(!a||!b||b.tellg()>=a.tellg())++failures;
    }
    if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
    std::remove(src);std::remove(dst);
    std::cout<<"REAP_Q81_LOSSLESS="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
