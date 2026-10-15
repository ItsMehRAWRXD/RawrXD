#include "deep2_tiered_moe.hpp"
#include <stdexcept>
#define CHECK(x) do { if (!(x)) throw std::runtime_error("CHECK failed: " #x); } while(false)
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace deep2::tiered;
int main(){
 const auto file=std::filesystem::temp_directory_path()/"deep2_tiered_moe_test.bin";
 {std::ofstream out(file,std::ios::binary|std::ios::trunc);for(int i=0;i<64;++i)out.put(static_cast<char>(i));}
 try {
  TensorIndex index;
  index.add({"a",file,0,16,0,0,2});
  index.add({"b",file,16,16,0,1,2});
  index.add({"c",file,32,16,0,2,2});
  CHECK(index.size()==3 && index.total_bytes()==48);
  Cache cache(32);
  {
   auto a=cache.acquire(index.at("a"));
   CHECK(a.bytes().size()==16 && std::to_integer<int>(a.bytes()[5])==5);
   auto b=cache.acquire(index.at("b"));
   bool rejected=false;
   try{auto c=cache.acquire(index.at("c"));(void)c;}catch(const std::runtime_error&){rejected=true;}
   CHECK(rejected);
   auto again=cache.acquire(index.at("a"));
   CHECK(cache.stats().hits==1);
  }
  {auto c=cache.acquire(index.at("c"));CHECK(std::to_integer<int>(c.bytes()[0])==32);}
  const auto s=cache.stats();
  CHECK(s.evictions==1 && s.resident_bytes==32 && s.pinned_bytes==0);
  CHECK(s.disk_reads==3 && s.disk_bytes==48);
  auto ok=admit({32,16,64,8,8,8},40);
  CHECK(ok.accepted && ok.usable_host==40);
  CHECK(!admit({32,16,64,8,8,8},41).accepted);
  CHECK(!admit({32,16,64,60,8,8},1).accepted);
  bool bounds=false;
  try{auto invalid=cache.acquire({"bad",file,60,16});(void)invalid;}catch(const std::runtime_error&){bounds=true;}
  CHECK(bounds);
  std::cout<<"DEEP2_TIERED_MOE_001 HOST_CACHE_PASS reads="<<s.disk_reads
           <<" evictions="<<s.evictions<<" resident="<<s.resident_bytes<<"\n";
 }catch(...){std::filesystem::remove(file);throw;}
 std::filesystem::remove(file);
}
