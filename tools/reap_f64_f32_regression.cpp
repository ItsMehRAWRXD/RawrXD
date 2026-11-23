#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_f64_src.gguf";const char* dst="reap_f64_dst.gguf";int failures=0;
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,1);WriteU64(o,0);
 WriteName(o,"custom.f64.vector");WriteU32(o,1);WriteU64(o,64);WriteU32(o,28);WriteU64(o,0);
 PadTo(o,32);
 for(int i=0;i<64;++i){double d=(i%2)?-2.5:1.25;uint64_t bits=0;std::memcpy(&bits,&d,8);WriteU64(o,bits);}}
 if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)!=RepackError::None)++failures;
 else {std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
 ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
 ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
 ReadU32(in,type);ReadU64(in,off);if(!in||type!=0||off!=0)++failures;
 const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);in.seekg(static_cast<std::streamoff>(start));
 for(int i=0;i<64;++i){uint32_t bits=0;if(!ReadU32(in,bits)){++failures;break;}
 float value=0;std::memcpy(&value,&bits,4);if(value!=((i%2)?-2.5f:1.25f))++failures;}
 std::ifstream a(src,std::ios::binary|std::ios::ate),b(dst,std::ios::binary|std::ios::ate);
 if(!a||!b||b.tellg()>=a.tellg())++failures;}
 if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_F64_F32="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
 return failures?1:0;
}
