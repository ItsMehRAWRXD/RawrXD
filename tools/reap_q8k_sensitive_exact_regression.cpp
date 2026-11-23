#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
static bool Run(bool exact) {
 const char* src="reap_q8k_sensitive_src.gguf",*dst="reap_q8k_sensitive_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,1);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,512);WriteU32(o,15);WriteU64(o,0);
 PadTo(o,32);
 for(int b=0;b<2;++b){
  // 0.5f is FP16 exact; the next representable F32 value is not.
  WriteU32(o,(!exact&&b==1)?0x3f000001u:0x3f000000u);
  for(int i=0;i<256;++i)o.put(static_cast<char>((i%127)-63));
  for(int i=0;i<16;++i)WriteU16(o,0);
 }}
 const auto result=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true);
 bool ok=result==(exact?RepackError::None:RepackError::Unsupported);
 if(exact&&ok){
  std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
  ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=bool(in)&&type==8&&off==0;
  const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
  in.seekg(static_cast<std::streamoff>(start));
  for(int b=0;b<2;++b)for(int group=0;group<8;++group){
   unsigned char block[34]={};
   if(!in.read(reinterpret_cast<char*>(block),34)){ok=false;break;}
   if(block[0]!=0||block[1]!=0x38)ok=false;
   for(int i=0;i<32;++i)if(block[i+2]!=static_cast<unsigned char>(((group*32+i)%127)-63))ok=false;
  }
 }
 if(std::filesystem::exists(std::string(dst)+".reap-part"))ok=false;
 std::remove(src);std::remove(dst);
 return ok;
}
int main(){
 const bool ok=Run(true)&&Run(false);
 std::cout<<"REAP_Q8K_SENSITIVE_EXACT="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
