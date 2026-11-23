#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
static bool Check(float v,bool expected) {
 const char* path="reap_f32_exact_probe.bin";
 {std::ofstream out(path,std::ios::binary);
  uint32_t bits=0;std::memcpy(&bits,&v,4);WriteU32(out,bits);}
 std::ifstream in(path,std::ios::binary);
 const bool actual=IsExactF32ToF16(in,0,4);
 in.close();std::remove(path);
 return actual==expected;
}
int main(){
 const bool ok=Check(1.0f,true)&&Check(-0.0f,true)&&
   Check(65504.0f,true)&&Check(1.0f/3.0f,false)&&
   Check(70000.0f,false)&&Check(1e-12f,false);
 std::cout<<"REAP_F32_EXACT_F16="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
