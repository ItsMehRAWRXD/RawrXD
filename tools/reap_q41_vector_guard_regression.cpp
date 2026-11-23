#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_q41_vector_guard_src.gguf",*dst="reap_q41_vector_guard_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,2);WriteU64(o,0);
 WriteName(o,"custom.vector");WriteU32(o,1);WriteU64(o,64);WriteU32(o,3);WriteU64(o,0);
 WriteName(o,"blk.0.attn_q.weight");WriteU32(o,2);WriteU64(o,32);WriteU64(o,32);WriteU32(o,3);WriteU64(o,64);
 PadTo(o,32);
 for(int k=0;k<2;++k){
  WriteU16(o,0x3800);WriteU16(o,0); // Not exact: minimum is not -8*d.
  for(int j=0;j<16;++j)o.put(static_cast<char>(j+k));
 }
 PadTo(o,32);
 for(int k=0;k<32;++k){
  WriteU16(o,0x3800);WriteU16(o,0);
  for(int j=0;j<16;++j)o.put(static_cast<char>(j+k));
 }}
 bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
 if(ok){
  std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
  ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=bool(in)&&type==3&&off==0;
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=ok&&bool(in)&&type==2&&off==64;
  std::ifstream a(src,std::ios::binary|std::ios::ate),d(dst,std::ios::binary|std::ios::ate);
  ok=ok&&bool(a)&&bool(d)&&d.tellg()<a.tellg();
 }
 if(std::filesystem::exists(std::string(dst)+".reap-part"))ok=false;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_Q41_VECTOR_GUARD="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
