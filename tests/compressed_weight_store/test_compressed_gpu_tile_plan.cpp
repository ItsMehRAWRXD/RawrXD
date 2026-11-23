#include "../../src/deep2/compression/CompressedGpuTilePlan.hpp"
#include <cassert>
#include <cstddef>
#include <limits>
#include <stdexcept>

int main(){
 using rawrxd::compression::PlanCompressedGpuTiles;
 const auto p=PlanCompressedGpuTiles(1000,777,144,1024);
 assert(p.size()==111);
 std::size_t rows=0,bytes=0;
 for(const auto& t:p){
  assert(t.first_row==rows);
  assert(t.byte_offset==t.first_row*144);
  assert(t.byte_count==t.row_count*144);
  assert(t.byte_count<=1024 || t.row_count==1);
  rows+=t.row_count;bytes+=t.byte_count;
 }
 assert(rows==777&&bytes==777*144);
 const auto one=PlanCompressedGpuTiles(4,4,4096,1024);
 assert(one.size()==4&&one.front().byte_count==4096);
 bool rejected=false;try{(void)PlanCompressedGpuTiles(4,5,16,64);}catch(const std::invalid_argument&){rejected=true;}
 assert(rejected);
 rejected=false;try{(void)PlanCompressedGpuTiles(std::numeric_limits<std::size_t>::max(),1,2,64);}catch(const std::overflow_error&){rejected=true;}
 assert(rejected);
 return 0;
}