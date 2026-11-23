#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 const char* src="reap_q51_sensitive_reject_src.gguf",*dst="reap_q51_sensitive_reject_dst.gguf";
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,1);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,64);WriteU32(o,7);WriteU64(o,0);
 PadTo(o,32);
 for(int b=0;b<2;++b){WriteU16(o,0x3800);WriteU16(o,b==0?0xc800:0x0000);
 for(int i=0;i<20;++i)o.put(static_cast<char>(i+b));}}
 const auto result=RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true);
 const bool ok=result==RepackError::Unsupported && !std::filesystem::exists(dst) &&
               !std::filesystem::exists(std::string(dst)+".reap-part");
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_Q51_SENSITIVE_REJECT="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
