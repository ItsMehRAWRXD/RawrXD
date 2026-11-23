#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_q8_exact_src.gguf",*dst="reap_q8_exact_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,2);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,8);WriteU64(o,0);
 WriteName(o,"blk.1.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,8);WriteU64(o,96);
 PadTo(o,32);
 for(int tensor=0;tensor<2;++tensor){
  for(int block=0;block<2;++block){
  WriteU16(o,0x3c00);
  for(int i=0;i<32;++i)o.put(static_cast<char>(tensor==0?(i%16-8):(i==0?127:0)));
 }
  }
  PadTo(o,32);
 }
 bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
 if(ok){
  std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
  ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=bool(in)&&type==2&&off==0;
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=ok&&bool(in)&&type==8&&off==64;
  const uint64_t data=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
  in.seekg(static_cast<std::streamoff>(data));
  for(int block=0;block<2;++block){
   unsigned char q[18]={};
   if(!in.read(reinterpret_cast<char*>(q),18)){ok=false;break;}
   if(q[0]!=0||q[1]!=0x3c)ok=false;
   for(int i=0;i<16;++i){
    const unsigned lo=static_cast<unsigned>(i%16);
    const unsigned hi=static_cast<unsigned>((i+16)%16);
    if(q[2+i]!=(lo|(hi<<4)))ok=false;
   }
  }
  std::ifstream a(src,std::ios::binary|std::ios::ate),d(dst,std::ios::binary|std::ios::ate);
  ok=ok&&bool(a)&&bool(d)&&d.tellg()<a.tellg();
 }
 if(std::filesystem::exists(std::string(dst)+".reap-part"))ok=false;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_Q8_EXACT_Q4="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
