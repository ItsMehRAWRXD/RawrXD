#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
static bool Check(unsigned mode) {
 const char* src="reap_f32_unaligned_src.gguf";
 const char* dst="reap_f32_unaligned_dst.gguf";
 std::remove(src);std::remove(dst);
 {std::ofstream out(src,std::ios::binary);
  WriteU32(out,0x46554747);WriteU32(out,3);
  WriteU64(out,1);WriteU64(out,0);
  WriteName(out,"blk.0.attn_q.weight");
  WriteU32(out,2);WriteU64(out,30);WriteU64(out,2);
  WriteU32(out,0);WriteU64(out,0);PadTo(out,32);
  for(unsigned i=0;i<60;++i) {
   float v=static_cast<float>(int(i%11)-5);
   if(mode==1 && i==17)v=1.0f/3.0f;
   if(mode==2 && i==17)v=70000.0f;
   uint32_t bits=0;std::memcpy(&bits,&v,4);WriteU32(out,bits);
  }
 }
 bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
 if(ok) {
  std::ifstream in(dst,std::ios::binary);
  uint32_t magic=0,version=0,nd=0,type=0;
  uint64_t tensors=0,kv=0,d0=0,d1=0,offset=0;
  std::string name;
  ok &= ReadU32(in,magic)&&ReadU32(in,version)&&ReadU64(in,tensors)&&
        ReadU64(in,kv)&&ReadName(in,name)&&ReadU32(in,nd)&&
        ReadU64(in,d0)&&ReadU64(in,d1)&&ReadU32(in,type)&&ReadU64(in,offset);
  ok &= magic==0x46554747 && type==(mode==2?0u:1u) &&
        d0==30 && d1==2 && offset==0;
 }
 std::remove(src);std::remove(dst);
 return ok;
}
int main() {
 const bool ok=Check(0)&&Check(1)&&Check(2);
 std::cout<<"REAP_F32_UNALIGNED_EXACT="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
