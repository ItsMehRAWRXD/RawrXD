#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
static bool Check(double value,bool expectedSuccess,uint16_t expectedHalf=0){
 const char* src="reap_f64_subnormal_src.bin";
 const char* dst="reap_f64_subnormal_dst.bin";
 {std::ofstream out(src,std::ios::binary);
  uint64_t bits=0;std::memcpy(&bits,&value,8);WriteU64(out,bits);}
 bool converted=false;
 {std::ifstream in(src,std::ios::binary);
  std::ofstream out(dst,std::ios::binary);
  converted=ConvertF64RangeToF16(in,out,0,8);}
 bool ok=converted==expectedSuccess;
 if(converted && expectedSuccess){
  std::ifstream in(dst,std::ios::binary);
  unsigned char bytes[2]={};
  ok &= bool(in.read(reinterpret_cast<char*>(bytes),2));
  ok &= (uint16_t(bytes[0])|(uint16_t(bytes[1])<<8))==expectedHalf;
 }
 std::remove(src);std::remove(dst);return ok;
}
int main(){
 bool ok=true;
 const double minSubnormal=std::ldexp(1.0,-24);
 ok &= Check(minSubnormal,true,0x0001);
 ok &= Check(-minSubnormal,true,0x8001);
 ok &= Check(minSubnormal*0.75,true,0x0001);
 ok &= Check(-minSubnormal*0.75,true,0x8001);
 ok &= Check(minSubnormal*0.25,false);
 ok &= Check(-minSubnormal*0.25,false);
 ok &= Check(1e-100,false);
 ok &= Check(0.0,true,0x0000);
 ok &= Check(-0.0,true,0x8000);
 std::cout<<"REAP_F64_F16_SUBNORMAL="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
