#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main(){
 bool ok=true;
 const char* src="reap_q41_vector_src.gguf";
 const char* dst="reap_q41_vector_dst.gguf";
 for(unsigned exact=0;exact<2;++exact){
  std::remove(src);std::remove(dst);
  {std::ofstream out(src,std::ios::binary);
   WriteU32(out,0x46554747);WriteU32(out,3);
   WriteU64(out,1);WriteU64(out,0);
   WriteName(out,"blk.0.attn_q.weight");WriteU32(out,1);
   WriteU64(out,32);WriteU32(out,3);WriteU64(out,0);
   PadTo(out,32);
   WriteU16(out,0x3c00); // d=1
   WriteU16(out,exact?0xc800:0xc700); // m=-8 or -7
   for(unsigned i=0;i<16;++i)out.put(static_cast<char>(i*7+3));
  }
  const RepackError result=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true);
  if(exact){
   ok &= result==RepackError::None;
   if(result==RepackError::None){
    std::ifstream in(dst,std::ios::binary);
    uint32_t u=0,nd=0,type=0;uint64_t n=0,offset=0;std::string name;
    ok &= ReadU32(in,u)&&ReadU32(in,u)&&ReadU64(in,n)&&ReadU64(in,n)&&
          ReadName(in,name)&&ReadU32(in,nd)&&ReadU64(in,n)&&
          ReadU32(in,type)&&ReadU64(in,offset);
    ok &= type==2 && offset==0;
   }
  }else{
   // The only tensor is ineligible: auto mode must refuse an
   // output with no actual tensor payload reduction.
   ok &= result==RepackError::Unsupported;
  }
 }
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_Q41_VECTOR_EXACT="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
