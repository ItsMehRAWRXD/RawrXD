#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_mixed_preserve_src.gguf",*dst="reap_mixed_preserve_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,2);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,256);WriteU32(o,15);WriteU64(o,0);
 WriteName(o,"custom.vector");WriteU32(o,1);WriteU64(o,64);WriteU32(o,0);WriteU64(o,320);
 PadTo(o,32);
 WriteU32(o,0x3f000001u);for(int i=0;i<256;++i)o.put(static_cast<char>(i%127));
 for(int i=0;i<16;++i)WriteU16(o,0);
 PadTo(o,32);
 for(int i=0;i<64;++i)WriteU32(o,0x3f000000u);
 }
 bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
 if(ok){
  std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
  ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=bool(in)&&type==15&&off==0;
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=ok&&bool(in)&&type==8&&off==320;
  const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);
  in.seekg(static_cast<std::streamoff>(start));
  unsigned char header[4]={};
  ok=ok&&bool(in.read(reinterpret_cast<char*>(header),4))&&header[0]==1&&header[1]==0&&header[2]==0&&header[3]==0x3f;
  std::ifstream a(src,std::ios::binary|std::ios::ate),b(dst,std::ios::binary|std::ios::ate);
  ok=ok&&bool(a)&&bool(b)&&b.tellg()<a.tellg();
 }
 if(std::filesystem::exists(std::string(dst)+".reap-part"))ok=false;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_MIXED_PRESERVE="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
