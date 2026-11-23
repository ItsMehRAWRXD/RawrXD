#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdint>
#include <cstring>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
 // Scale zero and minimum +zero are not required to satisfy a
 // particular affine-offset formula: the *used* midpoint codes
 // nevertheless reconstruct exactly as +zero in both layouts.
 unsigned char q4[16];std::memset(q4,0x88,sizeof(q4));
 unsigned char q5[16]={},hi[4];std::memset(hi,0xff,sizeof(hi));
 // For Q5_1, low nibbles zero and high bits set encode code 16.
 const bool q4exact=AffineBlockCodesBitExact(0.0f,0.0f,8,q4);
 const bool q5exact=AffineBlockCodesBitExact(0.0f,0.0f,16,q5,hi);
 // An off-midpoint zero code produces -zero in the symmetric
 // representation, but +zero in the affine representation.
 q4[0]=0x80;
 hi[0]=0xfe;
 const bool q4reject=!AffineBlockCodesBitExact(0.0f,0.0f,8,q4);
 const bool q5reject=!AffineBlockCodesBitExact(0.0f,0.0f,16,q5,hi);
 const bool ok=q4exact&&q5exact&&q4reject&&q5reject;
 std::cout<<"REAP_AFFINE_ZERO_MIDPOINT="<<(ok?"PASS":"FAIL")<<"\n";
 return ok?0:1;
}
