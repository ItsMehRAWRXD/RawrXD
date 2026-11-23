#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
 const char* src="reap_q8k_exact_src.gguf"; const char* dst="reap_q8k_exact_dst.gguf"; int failures=0;
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,1);WriteU64(o,0);
 WriteName(o,"blk.0.attn_norm.weight");WriteU32(o,1);WriteU64(o,256);WriteU32(o,15);WriteU64(o,0);PadTo(o,32);
 WriteU32(o,0x3f000000);for(int i=0;i<256;++i)o.put(static_cast<char>(i%32==0?-128:i%32-16));
 for(int i=0;i<16;++i)WriteU16(o,static_cast<uint16_t>(i%2?120:-136));}
 if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)!=RepackError::None)++failures;
 else {std::ifstream in(dst,std::ios::binary);uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
 ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);ReadName(in,name);ReadU32(in,nd);
 for(uint32_t i=0;i<nd;++i)ReadU64(in,n);ReadU32(in,type);ReadU64(in,off);
 if(!in||type!=8||off!=0)++failures;
 const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);in.seekg(static_cast<std::streamoff>(start));
 for(int b=0;b<8;++b){unsigned char bytes[34]={};
 if(!in.read(reinterpret_cast<char*>(bytes),34)){++failures;break;}
 if(bytes[0]!=0||bytes[1]!=0x38)++failures;
 for(int i=0;i<32;++i)if(static_cast<int8_t>(bytes[2+i])!=(i==0?-128:i-16))++failures;}
 std::ifstream a(src,std::ios::binary|std::ios::ate),b(dst,std::ios::binary|std::ios::ate);
 if(!a||!b||b.tellg()>=a.tellg())++failures;}
 if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_Q8K_EXACT="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
 return failures?1:0;
}
