#include "../../src/deep2/NativeTensorCompression.hpp"
#include <cassert>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <iostream>
using namespace RawrXD::TensorCompression;
int main() {
    const std::vector<uint8_t> repeated(4096,0x5a);
    auto r=Encode(repeated.data(),repeated.size());
    assert(r.encoding==Encoding::RLE && r.payload.size()<repeated.size());
    assert(Decode(r)==repeated);
    const std::vector<uint8_t> randomish={0,1,2,3,4,5,6,7,8,9};
    auto raw=Encode(randomish.data(),randomish.size());
    assert(raw.encoding==Encoding::Raw && Decode(raw)==randomish);
    const float f[]={1.0f,-2.0f,0.5f,65504.0f};
    auto half=Encode(f,sizeof(f),true,0.0f);
    assert(half.encoding==Encoding::F16 && half.payload.size()==sizeof(f)/2);
    auto decoded=Decode(half);
    assert(std::memcmp(decoded.data(),f,sizeof(f))==0);
    const float not_exact[]={1.0001f,2.0001f};
    auto preserved=Encode(not_exact,sizeof(not_exact),true,0.0f);
    assert(preserved.encoding!=Encoding::F16);
    const float specials[]={std::numeric_limits<float>::infinity(),1.0f};
    assert(Encode(specials,sizeof(specials),true,1.0f).encoding!=Encoding::F16);
    assert(ToHalf(1.0f)==0x3c00 && ToHalf(-0.0f)==0x8000);
    assert(Bits(FromHalf(0x3c00))==Bits(1.0f));
    assert(Bits(FromHalf(0x0001))==Bits(0x1p-24f));
    bool rejected=false;
    try { auto bad=r; bad.payload[0]=0; (void)Decode(bad); } catch(const std::invalid_argument&) {rejected=true;}
    assert(rejected);
    std::cout<<"native tensor compression tests PASS\n";
}
