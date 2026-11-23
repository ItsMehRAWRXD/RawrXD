#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 bool ok=true;
 for(unsigned mode=0;mode<2;++mode){
  const char* src="reap_q8_scale_edge_src.bin";
  const char* dst="reap_q8_scale_edge_dst.bin";
  std::remove(src);std::remove(dst);
  // Mode 0: nearest FP16 scale overflows; its lower neighbor
  // (65504) is finite. Mode 1: nearest FP16 scale underflows
  // to zero, while its upper neighbor is a valid subnormal.
  const float peak=mode==0?8388608.0f:0.000003f;
  {std::ofstream out(src,std::ios::binary);
   for(unsigned i=0;i<32;++i){
    const float value=i==0?peak:0.0f;
    uint32_t bits=0;std::memcpy(&bits,&value,4);WriteU32(out,bits);
   }}
  {std::ifstream in(src,std::ios::binary);
   std::ofstream out(dst,std::ios::binary);
   ok &= ConvertFloatRangeToQ8_0(in,out,0,128,false);}
  std::ifstream in(dst,std::ios::binary|std::ios::ate);
  ok &= bool(in)&&in.tellg()==std::streamoff(34);
  in.seekg(0);unsigned char block[34]={};
  ok &= bool(in.read(reinterpret_cast<char*>(block),34));
  const uint16_t h=uint16_t(block[0])|(uint16_t(block[1])<<8);
  const uint32_t bits=Float16ToFloat32Bits(h);
  float scale=0;std::memcpy(&scale,&bits,4);
  ok &= std::isfinite(scale)&&scale>0;
  ok &= block[2]!=0;
  in.close();std::remove(src);std::remove(dst);
 }
 std::cout<<"REAP_Q8_SCALE_EDGE="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
