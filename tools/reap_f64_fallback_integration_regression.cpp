#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
using namespace RawrXD::REAP;
static bool Check(double value,uint32_t expected) {
 const char* src="reap_f64_fallback_src.gguf";
 const char* dst="reap_f64_fallback_dst.gguf";
 std::remove(src);std::remove(dst);
 {std::ofstream out(src,std::ios::binary);
  WriteU32(out,0x46554747);WriteU32(out,3);
  WriteU64(out,1);WriteU64(out,0);
  WriteName(out,"output.weight");
  WriteU32(out,1);WriteU64(out,4);
  WriteU32(out,28);WriteU64(out,0);PadTo(out,32);
  for(unsigned i=0;i<4;++i) {
   double v=i==2?value:static_cast<double>(i);
   uint64_t bits=0;std::memcpy(&bits,&v,8);WriteU64(out,bits);
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
  ok &= magic==0x46554747 && type==expected && d0==4 && offset==0;
 }
 std::remove(src);std::remove(dst);
 return ok;
}
int main() {
 const bool ok=Check(1.0,1)&&Check(70000.0,0)&&
   Check(1e-100,0)&&Check(1e-300,28)&&
   Check(1e300,28)&&
   Check(std::numeric_limits<double>::infinity(),28);
 std::cout<<"REAP_F64_FALLBACK_INTEGRATION="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
