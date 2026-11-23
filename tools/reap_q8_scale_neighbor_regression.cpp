#include "../src/reap/NativeGGUFRepacker.hpp"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 bool ok=true;
 for(unsigned fmt=0;fmt<2;++fmt){
  const char* src="reap_neighbor_src.bin",*dst="reap_neighbor_dst.bin";
  std::remove(src);std::remove(dst);
  float values[32]={};
  for(unsigned i=0;i<32;++i)values[i]=i==0?-128.125f:i==1?127.0f:float(int(i%9)-4);
  if(fmt)for(float& v:values){uint32_t bits=0;std::memcpy(&bits,&v,4);bits=Float16ToFloat32Bits(Float32BitsToFloat16(bits));std::memcpy(&v,&bits,4);}
  {std::ofstream out(src,std::ios::binary);for(float v:values){uint32_t bits=0;std::memcpy(&bits,&v,4);if(fmt)WriteU16(out,Float32BitsToFloat16(bits));else WriteU32(out,bits);}}
  {std::ifstream in(src,std::ios::binary);std::ofstream out(dst,std::ios::binary);ok &= ConvertFloatRangeToQ8_0(in,out,0,fmt?64:128,fmt!=0);}
  std::ifstream in(dst,std::ios::binary|std::ios::ate);ok &= bool(in)&&in.tellg()==std::streamoff(34);in.seekg(0);
  unsigned char block[34]={};ok &= bool(in.read(reinterpret_cast<char*>(block),34));
  const uint16_t h=uint16_t(block[0])|(uint16_t(block[1])<<8);
  uint32_t decoded=Float16ToFloat32Bits(h);float scale=0;std::memcpy(&scale,&decoded,4);
  float positive=0,negative=0;for(float v:values){positive=std::max(positive,v);negative=std::max(negative,-v);}
  const float raw=float(std::max(double(positive)/127.0,double(negative)/128.0));
  uint32_t bits=0;std::memcpy(&bits,&raw,4);bits=Float16ToFloat32Bits(Float32BitsToFloat16(bits));
  float baseline=0;std::memcpy(&baseline,&bits,4);
  double chosenError=0,baselineError=0;
  for(unsigned i=0;i<32;++i){
   const int code=static_cast<int8_t>(block[i+2]);
   chosenError=std::max(chosenError,std::abs(double(values[i])-double(scale)*code));
   const double rounded=std::round(double(values[i])/baseline);
   const int q=int(std::max(-128.0,std::min(127.0,rounded)));
   baselineError=std::max(baselineError,std::abs(double(values[i])-double(baseline)*q));
  }
  ok &= std::isfinite(scale)&&chosenError<=baselineError+1e-6;
  in.close();std::remove(src);std::remove(dst);
 }
 std::cout<<"REAP_Q8_SCALE_NEIGHBOR="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
