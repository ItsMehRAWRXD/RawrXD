#pragma once
#include <cstdint>
namespace Deep2 { namespace kcost {
/* Caller supplies real meter/driver samples; estimator never invents watts. */
struct PowerSample { uint64_t ns; uint32_t milliWatts; };
inline uint64_t IntegrateMilliJ(const PowerSample*s,uint32_t n){
 if(!s||n<2)return 0; long double mj=0;
 for(uint32_t i=1;i<n;++i){
  uint64_t dt=s[i].ns-s[i-1].ns;
  uint64_t mw=((uint64_t)s[i].milliWatts+s[i-1].milliWatts)/2u;
  mj+=(long double)mw*(long double)dt/1000000000.0L;
 }
 return (uint64_t)mj;
}
}} 
