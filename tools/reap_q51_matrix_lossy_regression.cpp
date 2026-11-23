#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_q51_matrix_src.gguf",*dst="reap_q51_matrix_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,1);WriteU64(o,0);
 WriteName(o,"blk.0.attn_q.weight");WriteU32(o,2);WriteU64(o,32);WriteU64(o,32);
 WriteU32(o,7);WriteU64(o,0);PadTo(o,32);
 for(int b=0;b<32;++b){
  WriteU16(o,0x3800);WriteU16(o,0x0000);
  for(int i=0;i<20;++i)o.put(static_cast<char>(i+b));
 }}
 const auto result=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true);
 bool ok=result==RepackError::None;
 if(ok){
  std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
  ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
  ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
  ReadU32(in,type);ReadU64(in,off);ok=bool(in)&&type==6&&off==0;
  std::ifstream a(src,std::ios::binary|std::ios::ate),d(dst,std::ios::binary|std::ios::ate);
  ok=ok&&bool(a)&&bool(d)&&d.tellg()<a.tellg();
 }
 if(std::filesystem::exists(std::string(dst)+".reap-part"))ok=false;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_Q51_MATRIX_LOSSY="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
