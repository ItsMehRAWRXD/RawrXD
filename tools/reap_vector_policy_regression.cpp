#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
 const char* src="reap_vector_policy_src.gguf";const char* dst="reap_vector_policy_dst.gguf";int failures=0;
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,2);WriteU64(o,0);
 WriteName(o,"custom.vector");WriteU32(o,1);WriteU64(o,64);WriteU32(o,0);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,0);WriteU64(o,256);
 PadTo(o,32);for(int i=0;i<128;++i)WriteU32(o,0x3f800000u);}
 if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)!=RepackError::None)++failures;
 else {std::ifstream in(dst,std::ios::binary);
 uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
 ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
 ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
 ReadU32(in,type);ReadU64(in,off);if(!in||name!="custom.vector"||type!=8||off!=0)++failures;
 ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
 ReadU32(in,type);ReadU64(in,off);
 if(!in||name!="blk.0.attn_norm.weight"||type!=1||off!=96)++failures;
 std::ifstream a(src,std::ios::binary|std::ios::ate),b(dst,std::ios::binary|std::ios::ate);
 if(!a||!b||b.tellg()>=a.tellg())++failures;}
 if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_VECTOR_POLICY="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
 return failures?1:0;
}
