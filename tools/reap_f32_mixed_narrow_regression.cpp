#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_f32_mixed_src.gguf",*dst="reap_f32_mixed_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,2);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,0);WriteU64(o,0);
 WriteName(o,"blk.1.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,0);WriteU64(o,256);
 PadTo(o,32);
 for(int tensor=0;tensor<2;++tensor)
  for(int i=0;i<64;++i){
   float v=(tensor==0&&i==0)?100000.0f:1.0f;
   uint32_t bits=0;std::memcpy(&bits,&v,4);WriteU32(o,bits);
  }
 }
 bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
 if(ok){
  std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
  ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=bool(in)&&type==0&&off==0;
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=ok&&bool(in)&&type==1&&off==256;
  std::ifstream a(src,std::ios::binary|std::ios::ate),d(dst,std::ios::binary|std::ios::ate);
  ok=ok&&bool(a)&&bool(d)&&d.tellg()<a.tellg();
 }
 if(std::filesystem::exists(std::string(dst)+".reap-part"))ok=false;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_F32_MIXED_NARROW="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
