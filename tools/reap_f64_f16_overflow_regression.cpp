#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
static bool Test(double v,bool expected,uint16_t code=0){
 const char* src="reap_f64_overflow_src.bin";
 const char* dst="reap_f64_overflow_dst.bin";
 {std::ofstream out(src,std::ios::binary);
  uint64_t bits=0;std::memcpy(&bits,&v,8);WriteU64(out,bits);}
 bool converted=false;
 {std::ifstream in(src,std::ios::binary);
  std::ofstream out(dst,std::ios::binary);
  converted=ConvertF64RangeToF16(in,out,0,8);}
 bool ok=converted==expected;
 if(converted && expected){
  std::ifstream in(dst,std::ios::binary);
  unsigned char bytes[2]={};
  ok &= bool(in.read(reinterpret_cast<char*>(bytes),2));
  ok &= (uint16_t(bytes[0])|(uint16_t(bytes[1])<<8))==code;
 }
 std::remove(src);std::remove(dst);return ok;
}
int main(){
 bool ok=true;
 ok &= Test(65504.0,true,0x7bff);
 ok &= Test(-65504.0,true,0xfbff);
 ok &= Test(65504.01,false);
 ok &= Test(-65504.01,false);
 ok &= Test(70000.0,false);
 ok &= Test(-70000.0,false);
 ok &= Test(1e300,false);
 std::cout<<"REAP_F64_F16_OVERFLOW="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
