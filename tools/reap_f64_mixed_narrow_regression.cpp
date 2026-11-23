#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_f64_mixed_src.gguf",*dst="reap_f64_mixed_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,3);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,28);WriteU64(o,0);
 WriteName(o,"blk.1.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,28);WriteU64(o,512);
 WriteName(o,"blk.2.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,28);WriteU64(o,1024);
 PadTo(o,32);
 for(int tensor=0;tensor<3;++tensor)
  for(int i=0;i<64;++i){
   const double v=(i==0&&tensor==0)?100000.0:
                  (i==0&&tensor==2)?1.0e300:1.0;
   uint64_t bits=0;std::memcpy(&bits,&v,8);WriteU64(o,bits);
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
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=ok&&bool(in)&&type==28&&off==384;
  std::ifstream a(src,std::ios::binary|std::ios::ate),d(dst,std::ios::binary|std::ios::ate);
  ok=ok&&bool(a)&&bool(d)&&d.tellg()<a.tellg();
 }
 if(std::filesystem::exists(std::string(dst)+".reap-part"))ok=false;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_F64_MIXED_NARROW="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
