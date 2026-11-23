#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main(){
 bool ok=true;
 const char* src="reap_f64_f16_src.gguf";
 const char* dst="reap_f64_f16_dst.gguf";
 for(unsigned mode=0;mode<3;++mode){
  std::remove(src);std::remove(dst);
  {std::ofstream out(src,std::ios::binary);
   WriteU32(out,0x46554747);WriteU32(out,3);
   WriteU64(out,1);WriteU64(out,0);
   WriteName(out,"blk.0.attn_norm.weight");
   WriteU32(out,1);WriteU64(out,4);WriteU32(out,28);WriteU64(out,0);
   PadTo(out,32);
   for(unsigned i=0;i<4;++i){
    double v=mode==0?double(int(i)-2):
             mode==1?100000.0:1e-12;
    uint64_t bits=0;std::memcpy(&bits,&v,8);
    WriteU64(out,bits);
   }
  }
  const RepackError result=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true);
  if(mode==0){
   ok &= result==RepackError::None;
   if(result==RepackError::None){
    std::ifstream in(dst,std::ios::binary);
    uint32_t magic=0,version=0,nd=0,type=0;
    uint64_t tensors=0,kv=0,d0=0,offset=0;
    std::string name;
    ok &= ReadU32(in,magic)&&ReadU32(in,version)&&ReadU64(in,tensors)&&
          ReadU64(in,kv)&&ReadName(in,name)&&ReadU32(in,nd)&&
          ReadU64(in,d0)&&ReadU32(in,type)&&ReadU64(in,offset);
    ok &= type==1 && d0==4 && offset==0;
   }
  } else ok &= result==RepackError::Output;
 }
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_F64_F16="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
