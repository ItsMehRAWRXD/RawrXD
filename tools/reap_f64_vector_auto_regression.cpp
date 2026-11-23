#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
static bool Check(unsigned dims,bool matrix){
 const char* src="reap_f64_vector_src.gguf";
 const char* dst="reap_f64_vector_dst.gguf";
 std::remove(src);std::remove(dst);
 {std::ofstream out(src,std::ios::binary);
  WriteU32(out,0x46554747);WriteU32(out,3);
  WriteU64(out,1);WriteU64(out,0);
  WriteName(out,"blk.0.attn_q.weight");
  WriteU32(out,dims);WriteU64(out,4);
  if(dims==2)WriteU64(out,matrix?2:1);
  WriteU32(out,28);WriteU64(out,0);
  PadTo(out,32);
  for(unsigned i=0;i<(matrix?8u:4u);++i){
   double value=static_cast<double>(int(i)-2);
   uint64_t bits=0;std::memcpy(&bits,&value,8);WriteU64(out,bits);
  }
 }
 bool ok=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None;
 if(ok){
  std::ifstream in(dst,std::ios::binary);
  uint32_t magic=0,version=0,nd=0,type=0;
  uint64_t tensors=0,kv=0,d0=0,d1=0,offset=0;
  std::string name;
  ok &= ReadU32(in,magic)&&ReadU32(in,version)&&ReadU64(in,tensors)&&
        ReadU64(in,kv)&&ReadName(in,name)&&ReadU32(in,nd)&&ReadU64(in,d0);
  if(dims==2)ok &= ReadU64(in,d1);
  ok &= ReadU32(in,type)&&ReadU64(in,offset);
  ok &= type==(matrix?0u:1u) && offset==0 && d0==4;
 }
 std::remove(src);std::remove(dst);
 return ok;
}
int main(){
 const bool ok=Check(1,false)&&Check(2,false)&&Check(2,true);
 std::cout<<"REAP_F64_VECTOR_AUTO="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
