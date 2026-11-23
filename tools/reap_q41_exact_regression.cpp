#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
 const char* src="reap_q41_exact_src.gguf",*dst="reap_q41_exact_dst.gguf";
 int failures=0;
 {std::ofstream o(src,std::ios::binary);
 WriteU32(o,0x46554747);WriteU32(o,3);WriteU64(o,1);WriteU64(o,0);
 WriteName(o,"blk.0.ffn_up.weight");WriteU32(o,2);
 WriteU64(o,32);WriteU64(o,2);WriteU32(o,3);WriteU64(o,0);PadTo(o,32);
 for(int b=0;b<2;++b){WriteU16(o,0x3800);WriteU16(o,0xc400);
 for(int i=0;i<16;++i)o.put(static_cast<char>((i+b)*13+7));}}
 if(RepackGGUF(src,dst,UINT64_MAX,false,false,false,false,true)!=RepackError::None)++failures;
 else {std::ifstream in(dst,std::ios::binary);
 uint32_t u=0,nd=0,type=0;uint64_t n=0,off=0;std::string name;
 ReadU32(in,u);ReadU32(in,u);ReadU64(in,n);ReadU64(in,n);ReadName(in,name);ReadU32(in,nd);
 for(uint32_t i=0;i<nd;++i)ReadU64(in,n);ReadU32(in,type);ReadU64(in,off);
 if(!in||type!=2||off!=0)++failures;
 const auto start=(static_cast<uint64_t>(in.tellg())+31)&~uint64_t(31);in.seekg(static_cast<std::streamoff>(start));
 for(int b=0;b<2;++b){unsigned char bytes[18]={};
 if(!in.read(reinterpret_cast<char*>(bytes),18)){++failures;break;}
 if(bytes[0]!=0||bytes[1]!=0x38)++failures;
 for(int i=0;i<16;++i)if(bytes[2+i]!=static_cast<unsigned char>((i+b)*13+7))++failures;}
 std::ifstream a(src,std::ios::binary|std::ios::ate),b(dst,std::ios::binary|std::ios::ate);
 if(!a||!b||b.tellg()>=a.tellg())++failures;}
 if(std::filesystem::exists(std::string(dst)+".reap-part"))++failures;
 std::remove(src);std::remove(dst);
 std::cout<<"REAP_Q41_EXACT="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
 return failures?1:0;
}
