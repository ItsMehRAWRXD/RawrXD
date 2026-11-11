#include "GGUFDirectoryAuthority.hpp"
#include <fstream>
#include <cassert>
#include <iostream>
#include <cstdio>
using namespace Deep2::Directory;
static void u32(std::ofstream& f,uint32_t v){for(int i=0;i<4;i++)f.put(static_cast<char>(v>>(i*8)));}
static void u64(std::ofstream& f,uint64_t v){u32(f,static_cast<uint32_t>(v));u32(f,static_cast<uint32_t>(v>>32));}
static void str(std::ofstream& f,const std::string& s){u64(f,s.size());f.write(s.data(),static_cast<std::streamsize>(s.size()));}
int main(){const char* p="directory_fixture.gguf";{
 std::ofstream f(p,std::ios::binary);f.write("GGUF",4);u32(f,3);u64(f,1);u64(f,2);
 str(f,"general.architecture");u32(f,8);str(f,"fixture");str(f,"general.alignment");u32(f,4);u32(f,32);
 str(f,"blk.0.ffn_gate_exps.weight");u32(f,2);u64(f,4);u64(f,8);u32(f,0);u64(f,0);
 auto pos=static_cast<uint64_t>(f.tellp());while(pos++%32!=0)f.put(0);for(int i=0;i<128;i++)f.put(0);
 }
 auto geo=[](uint32_t t,uint64_t& be,uint64_t& bb){if(t!=0)return false;be=1;bb=4;return true;};
 auto m=inspect(p,geo);if(!m.errors.empty()){std::cerr<<m.errors.front()<<'\n';return 1;}assert(m.architecture=="fixture");assert(m.tensors.size()==1);assert(m.tensors[0].bytes==128);
 auto reject=inspect(p,[](uint32_t,uint64_t&,uint64_t&){return false;});assert(!reject.errors.empty());
 std::remove(p);std::cout<<"GGUF_DIRECTORY_AUTHORITY_PASS\n";
}
