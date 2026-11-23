#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
 const char* src="reap_overlap_preflight_src.gguf",*dst="reap_overlap_preflight_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,2);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,3);WriteU64(o,0);
 WriteName(o,"custom.vector");WriteU32(o,1);WriteU64(o,64);WriteU32(o,3);WriteU64(o,32);
 PadTo(o,32);
 for(int b=0;b<4;++b) {
  WriteU16(o,0x3800);WriteU16(o,0xc400);
  for(int i=0;i<16;++i)o.put(static_cast<char>(i+b));
 }}
 // Both offsets are aligned and individually in bounds, but the 40-byte
 // tensor payloads overlap across [0,40) and [32,72).
 const auto result=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true);
 const bool ok=result==RepackError::Format &&
               !std::filesystem::exists(dst) &&
               !std::filesystem::exists(std::string(dst)+".reap-part");
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_OVERLAP_PREFLIGHT="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
