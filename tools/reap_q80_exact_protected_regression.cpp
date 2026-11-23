#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
static bool Check(bool exact) {
 const char* src="reap_q80_exact_src.gguf";
 const char* dst="reap_q80_exact_dst.gguf";
 std::remove(src);std::remove(dst);
 {std::ofstream out(src,std::ios::binary);
  WriteU32(out,0x46554747);WriteU32(out,3);
  WriteU64(out,1);WriteU64(out,0);
  WriteName(out,"output.weight");
  WriteU32(out,1);WriteU64(out,32);
  WriteU32(out,8);WriteU64(out,0);PadTo(out,32);
  WriteU16(out,0x3c00);
  for(unsigned i=0;i<32;++i) {
   int q=int(i%16)-8;
   if(!exact && i==31)q=8;
   out.put(static_cast<char>(q));
  }
 }
 bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
 if(ok) {
  std::ifstream in(dst,std::ios::binary);
  uint32_t magic=0,version=0,nd=0,type=0;
  uint64_t tensors=0,kv=0,d0=0,offset=0;
  std::string name;
  ok &= ReadU32(in,magic)&&ReadU32(in,version)&&ReadU64(in,tensors)&&
        ReadU64(in,kv)&&ReadName(in,name)&&ReadU32(in,nd)&&
        ReadU64(in,d0)&&ReadU32(in,type)&&ReadU64(in,offset);
  ok &= magic==0x46554747 && type==(exact?2u:8u) && d0==32 && offset==0;
 }
 std::remove(src);std::remove(dst);
 return ok;
}
int main() {
 const bool ok=Check(true)&&Check(false);
 std::cout<<"REAP_Q80_EXACT_PROTECTED="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
