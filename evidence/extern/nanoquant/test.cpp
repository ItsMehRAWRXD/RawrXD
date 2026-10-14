#include "nanoquant_residency.hpp"
#include <cassert>
#include <cstdio>
#include <random>
#include <vector>
int main(){
  std::mt19937_64 rng(0xabc123);
  for(size_t n: {size_t(0),size_t(1),size_t(2),size_t(3),size_t(127),size_t(128),size_t(129),size_t(256),size_t(8192),size_t(65536)}){
    for(int mode=0;mode<3;++mode){
      std::vector<uint8_t> src(n);
      for(size_t i=0;i<n;++i) src[i]=mode==0?uint8_t(rng()):mode==1?uint8_t(i/1000):uint8_t(i%7);
      auto p=rawrxd::nanoquant::plan(src.data(),src.size());
      std::vector<uint8_t> restored(n);
      assert(rawrxd::nanoquant::restore(p,restored.data(),restored.size()));
      assert(src==restored);
    }
  }
  uint8_t bad[]={0x80}; uint8_t dst[3];
  assert(!rawrxd::nanoquant::decode(bad,sizeof(bad),dst,sizeof(dst)));
  std::puts("NANOQUANT_LOSSLESS_ROUNDTRIP_PASS 30/30; malformed stream rejected");
}
