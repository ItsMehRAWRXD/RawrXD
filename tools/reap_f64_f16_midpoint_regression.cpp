#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_f64_round_src.bin";
 const char* dst="reap_f64_round_dst.bin";
 const double midpoint=1.0+std::ldexp(1.0,-11);
 const double epsilon=std::ldexp(1.0,-30);
 const double values[]={midpoint+epsilon,midpoint-epsilon,midpoint,
                        -midpoint-epsilon,-midpoint+epsilon,-midpoint};
 const uint16_t expected[]={0x3c01,0x3c00,0x3c00,0xbc01,0xbc00,0xbc00};
 {std::ofstream out(src,std::ios::binary);
  for(double v:values){uint64_t bits=0;std::memcpy(&bits,&v,8);WriteU64(out,bits);}
 }
 bool ok=false;
 {std::ifstream in(src,std::ios::binary);std::ofstream out(dst,std::ios::binary);
  ok=ConvertF64RangeToF16(in,out,0,sizeof(values));}
 {std::ifstream in(dst,std::ios::binary|std::ios::ate);
  ok &= bool(in)&&in.tellg()==std::streamoff(sizeof(expected));
  in.seekg(0);
  for(unsigned i=0;i<sizeof(expected)/sizeof(expected[0]);++i){
   unsigned char bytes[2]={};ok &= bool(in.read(reinterpret_cast<char*>(bytes),2));
   const uint16_t h=uint16_t(bytes[0])|(uint16_t(bytes[1])<<8);
   ok &= h==expected[i];
  }
 }
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_F64_F16_MIDPOINT="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
