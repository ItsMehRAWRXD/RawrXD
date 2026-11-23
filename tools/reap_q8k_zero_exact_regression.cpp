#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_q8k_zero_src.gguf",*dst="reap_q8k_zero_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,1);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,512);
 WriteU32(o,15);WriteU64(o,0);PadTo(o,32);
 for(int block=0;block<2;++block){
  const uint32_t bits=block==0?0x3e99999au:0xbe99999au;
  WriteU32(o,bits);
  for(int i=0;i<256;++i)o.put(0);
  for(int i=0;i<16;++i)WriteU16(o,0);
 }}
 bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
 if(ok){
  std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
  ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=bool(in)&&type==8&&off==0;
  const auto data=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
  in.seekg(static_cast<std::streamoff>(data));
  for(int block=0;block<2;++block){
   for(int group=0;group<8;++group){
    unsigned char q[34]={};
    if(!in.read(reinterpret_cast<char*>(q),34)){ok=false;break;}
    const uint16_t expected=block==0?0x0000u:0x8000u;
    const uint16_t scale=uint16_t(q[0])|(uint16_t(q[1])<<8);
    if(scale!=expected)ok=false;
    for(int i=2;i<34;++i)if(q[i]!=0)ok=false;
   }
  }
  std::ifstream a(src,std::ios::binary|std::ios::ate),d(dst,std::ios::binary|std::ios::ate);
  ok=ok&&bool(a)&&bool(d)&&d.tellg()<a.tellg();
 }
 if(std::filesystem::exists(std::string(dst)+".reap-part"))ok=false;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_Q8K_ZERO_EXACT="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
