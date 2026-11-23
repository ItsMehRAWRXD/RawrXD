#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
 const char* src="reap_q51_mixed_src.gguf",*dst="reap_q51_mixed_dst.gguf";int failures=0;
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,1);WriteU64(o,0);
 WriteName(o,"custom.vector");WriteU32(o,1);WriteU64(o,64);WriteU32(o,7);WriteU64(o,0);
 PadTo(o,32);
 // First block is exactly compatible with Q5_0; second must requantize.
 for(int b=0;b<2;++b){WriteU16(o,0x3800);WriteU16(o,b==0?0xc800:0x0000);
 for(int i=0;i<4;++i)o.put(0);
 for(int i=0;i<16;++i)o.put(static_cast<char>(0x88));}}
 if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)!=RepackError::None)++failures;
 else {std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
 ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);
 ReadName(in,name);ReadU32(in,nd);for(uint32_t i=0;i<nd;++i)ReadU64(in,n);
 ReadU32(in,type);ReadU64(in,off);if(!in||type!=6||off!=0)++failures;
 const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);in.seekg(static_cast<std::streamoff>(start));
 unsigned char first[22]={},second[22]={};
 if(!in.read(reinterpret_cast<char*>(first),22)||!in.read(reinterpret_cast<char*>(second),22))++failures;
 else {
  if(first[0]!=0||first[1]!=0x38)++failures;
  for(int i=0;i<4;++i)if(first[2+i]!=0)++failures;
  for(int i=0;i<16;++i)if(first[6+i]!=0x88)++failures;
  // The second Q5_1 block represents +4.0 for every element.
  const uint16_t h=uint16_t(second[0])|(uint16_t(second[1])<<8);
  const uint32_t bits=Float16ToFloat32Bits(h);float scale=0;std::memcpy(&scale,&bits,4);
  for(int i=0;i<32;++i){
   const int qh=(second[2+i/8]>>(i%8))&1;
   const int ql=i<16?(second[6+i]&15):(second[6+i-16]>>4);
   const float value=scale*float((ql|(qh<<4))-16);
   if(!std::isfinite(value)||std::abs(value-4.0f)>0.5f)++failures;
  }
 }
 std::ifstream a(src,std::ios::binary|std::ios::ate),b(dst,std::ios::binary|std::ios::ate);
 if(!a||!b||b.tellg()>=a.tellg())++failures;}
 if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_Q51_MIXED="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
 return failures?1:0;
}
