#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
using namespace RawrXD::REAP;
static void Fixture(const char* path,double value) {
 std::ofstream out(path,std::ios::binary);
 WriteU32(out,0x46554747);WriteU32(out,3);WriteU64(out,1);WriteU64(out,0);
 WriteName(out,"custom.f64.vector");WriteU32(out,1);WriteU64(out,64);WriteU32(out,28);WriteU64(out,0);
 PadTo(out,32);
 uint64_t bits=0;std::memcpy(&bits,&value,8);
 for(int i=0;i<64;++i)WriteU64(out,bits);
}
int main(){
 const char* src="reap_f64_reject_src.gguf";const char* dst="reap_f64_reject_dst.gguf";
 int failures=0;
 const double invalid[]={std::numeric_limits<double>::infinity(),
                         std::numeric_limits<double>::quiet_NaN(),
                         std::numeric_limits<double>::max(),
                         std::numeric_limits<double>::denorm_min()};
 for(double value:invalid) {
  Fixture(src,value);
  {std::ofstream out(dst,std::ios::binary);out<<"UNCHANGED";}
  if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)==RepackError::None)++failures;
  {std::ifstream in(dst,std::ios::binary);std::string text;
   std::getline(in,text);if(text!="UNCHANGED")++failures;}
  if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
  std::remove(src);std::remove(dst);
 }
 std::cout<<"REAP_F64_REJECT="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
 return failures?1:0;
}
