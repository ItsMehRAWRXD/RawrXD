#include "rawrxd/compressed_block_store.hpp"
#include <cassert>
#include <cstdint>
#include <vector>
using namespace rawrxd::compression;
static bool decode(const std::uint8_t* s,std::size_t n,std::uint8_t* d,std::size_t cap){
 if(n!=cap)return false;for(std::size_t i=0;i<n;++i)d[i]=s[i];return true;
}
int main(){
 std::vector<std::uint8_t> data(96);for(std::size_t i=0;i<data.size();++i)data[i]=std::uint8_t(i^0x5a);
 std::vector<CompressedBlock> b{{0,32,0,32,crc32_bytes(data.data(),32)},
 {32,32,32,32,crc32_bytes(data.data()+32,32)},
 {64,32,64,32,crc32_bytes(data.data()+64,32)}};
 CompressedBlockStore store(data,b,data.size(),32,decode);std::uint8_t range[40]{};
 assert(store.read(24,sizeof(range),range));for(std::size_t i=0;i<40;++i)assert(range[i]==data[24+i]);
 assert(store.cached_decoded_bytes()<=32);std::uint8_t tail[8]{};
 assert(store.read(88,8,tail));for(std::size_t i=0;i<8;++i)assert(tail[i]==data[88+i]);
 assert(!store.read(90,8,tail));assert(store.read(96,0,nullptr));
 auto bad=b;bad[0].raw_crc32^=1u;CompressedBlockStore corrupt(data,bad,data.size(),64,decode);
 std::uint8_t first[4]{};assert(!corrupt.read(0,4,first));
 bool rejected=false;try{auto gap=b;gap[1].logical_offset++;CompressedBlockStore invalid(data,gap,data.size(),64,decode);}catch(...){rejected=true;}
 assert(rejected);return 0;
}