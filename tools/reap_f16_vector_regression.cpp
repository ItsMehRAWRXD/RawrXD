#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
 const char* src="reap_f16_vector_src.gguf";const char* dst="reap_f16_vector_dst.gguf";int failures=0;
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,1);WriteU64(o,0);
 WriteName(o,"custom.vector");WriteU32(o,1);WriteU64(o,64);WriteU32(o,1);WriteU64(o,0);
 PadTo(o,32);for(int i=0;i<64;++i)WriteU16(o,0x3c00u);}
 if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)!=RepackError::None)++failures;
 else {std::ifstream in(dst,std::ios::binary);
 uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
 ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);ReadName(in,name);ReadU32(in,nd);
 for(uint32_t i=0;i<nd;++i)ReadU64(in,n);ReadU32(in,type);ReadU64(in,off);
 if(!in||type!=8||off!=0)++failures;
 const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
 in.seekg(static_cast<std::streamoff>(start));
 for(int b=0;b<2;++b){unsigned char bytes[34]={};
 if(!in.read(reinterpret_cast<char*>(bytes),34)){++failures;break;}
 uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
 uint32_t bits=Float16ToFloat32Bits(h);float scale=0;std::memcpy(&scale,&bits,4);
 for(int i=0;i<32;++i){float value=scale*static_cast<int8_t>(bytes[i+2]);
 if(!std::isfinite(value)||std::abs(value-1.0f)>0.02f)++failures;}}
 std::ifstream a(src,std::ios::binary|std::ios::ate),b(dst,std::ios::binary|std::ios::ate);
 if(!a||!b||b.tellg()>=a.tellg())++failures;}
 if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_F16_VECTOR="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
 return failures?1:0;
}
