#include "../src/reap/NativeGGUFRepacker.hpp"
#include <iostream>
using namespace RawrXD::REAP;
int main() {
 int failures=0;
 if(!AffineCodesBitExact(0.5f,-4.0f,8,16))++failures;
 if(!AffineCodesBitExact(0.5f,-8.0f,16,32))++failures;
 if(AffineCodesBitExact(0.5f,0.0f,8,16))++failures;
 if(AffineCodesBitExact(0.5f,0.0f,16,32))++failures;
 if(AffineCodesBitExact(0.0f,-0.0f,8,16))++failures;
 std::cout<<"REAP_AFFINE_PARITY="<<(failures?"FAIL":"PASS")<<" failures="<<failures<<"\n";
 return failures?1:0;
}
