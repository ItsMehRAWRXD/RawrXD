#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
using namespace RawrXD::REAP;
static bool Probe(double value,bool f16,bool expected) {
 const char* path="reap_f64_auto_probe.bin";
 {std::ofstream out(path,std::ios::binary);
  uint64_t bits=0;std::memcpy(&bits,&value,8);WriteU64(out,bits);}
 std::ifstream in(path,std::ios::binary);
 const bool actual=f16?CanConvertF64ToF16(in,0,8):
                       CanConvertF64ToF32(in,0,8);
 in.close();std::remove(path);
 return actual==expected;
}
int main() {
 bool ok=true;
 ok &= Probe(1.0,true,true);
 ok &= Probe(-0.0,true,true);
 ok &= Probe(65504.0,true,true);
 ok &= Probe(65505.0,true,false);
 ok &= Probe(0x1p-25,true,false);
 ok &= Probe(0x1p-24,true,true);
 ok &= Probe(1e-100,true,false);
 ok &= Probe(1e-100,false,true);
 ok &= Probe(1e-300,false,false);
 ok &= Probe(1e300,false,false);
 ok &= Probe(std::numeric_limits<double>::infinity(),false,false);
 ok &= Probe(std::numeric_limits<double>::quiet_NaN(),true,false);
 std::cout<<"REAP_F64_AUTO_PREFLIGHT="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
