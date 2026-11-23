#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdint>
#include <cstring>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 unsigned char low[16]={},high[4]={};
 // Every used code is zero. Non-power-of-two scales can have
 // rounding differences for unused codes; those must not block
 // an exact conversion of the actual block.
 const float d=0.300048828125f;
 const float m=-8.0f*d;
 bool ok=AffineBlockCodesBitExact(d,m,8,low);
 // The Q5 high plane must be read separately and changes actual codes.
 const float d5=0.300048828125f;
 const float m5=-16.0f*d5;
 const bool q5zero=AffineBlockCodesBitExact(d5,m5,16,low,high);
 high[0]=1;
 const bool q5changed=AffineBlockCodesBitExact(d5,m5,16,low,high);
 // Compare against an independent per-code bitwise reconstruction.
 auto expected=[&](unsigned q)->bool {
  const float x=d5*static_cast<float>(q)+m5;
  const float y=d5*static_cast<float>(static_cast<int>(q)-16);
  uint32_t a=0,c=0;std::memcpy(&a,&x,4);std::memcpy(&c,&y,4);
  return a==c;
 };
 ok=ok&&(q5zero==expected(0))&&
    (q5changed==(expected(0)&&expected(16)));
 // Signed-zero differences must not be silently accepted.
 unsigned char allMid[16];std::memset(allMid,0x00,sizeof(allMid));
 ok=ok&&!AffineBlockCodesBitExact(0.0f,+0.0f,8,allMid);
 std::cout<<"REAP_AFFINE_USED_CODES="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
