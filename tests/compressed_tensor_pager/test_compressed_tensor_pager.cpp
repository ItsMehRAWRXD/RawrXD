#include "CompressedTensorPager.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
int main(){
 std::vector<uint8_t> model(1024*1024+37);
 for(size_t i=0;i<model.size();++i) model[i]=static_cast<uint8_t>((i/4096)%7);
 deep2::CompressedTensorPager pager(model.size(),[&](uint64_t off,uint64_t n,uint8_t*out){
   if(off>model.size()||n>model.size()-off)return false;
   std::memcpy(out,model.data()+off,static_cast<size_t>(n));return true;
 },64*1024,128*1024);
 std::vector<uint8_t> out(150*1024);
 assert(pager.read(60*1024,out.size(),out.data()));
 assert(std::memcmp(out.data(),model.data()+60*1024,out.size())==0);
 auto stats=pager.stats(); assert(stats.residentBytes<=128*1024);
 assert(stats.compressedPages>0 && stats.cacheMisses>=3);
 assert(!pager.read(model.size()-1,2,out.data()));
 pager.clear(); assert(pager.stats().residentBytes==0);
 std::cout<<"lazy compressed tensor pager tests passed\n";
}
