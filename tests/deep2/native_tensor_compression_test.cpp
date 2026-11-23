#include "../../src/deep2/NativeTensorCompression.hpp"
#include <cassert>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cmath>
#include <limits>
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
    // BF16 keeps F32's exponent range when FP16 would overflow.
    const float wide[]={1.0e20f,-1.0e20f,3.25f,-0.0f};
    auto bf16=Encode(wide,sizeof(wide),true,1.0e18f,true);
    assert(bf16.encoding==Encoding::BF16 && bf16.payload.size()==sizeof(wide)/2);
    auto wideDecoded=Decode(bf16);
    for(size_t i=0;i<4;++i) {
        float value; std::memcpy(&value,wideDecoded.data()+i*4,4);
        assert(std::isfinite(value));
        assert(std::fabs(value-wide[i])<=1.0e18f);
    }
    assert(ToBFloat16(1.0f)==0x3f80);
    assert(Bits(FromBFloat16(0x3f80))==Bits(1.0f));
    const float exact_bf[]={1.0f,-2.0f,0.5f,4.0f};
    auto exactBf=Encode(exact_bf,sizeof(exact_bf),false,0.0f,true);
    assert(exactBf.encoding==Encoding::BF16 && Decode(exactBf).size()==sizeof(exact_bf));
    const float bfSpecial[]={std::numeric_limits<float>::quiet_NaN(),1.0f};
    assert(Encode(bfSpecial,sizeof(bfSpecial),false,1.0f,true).encoding!=Encoding::BF16);
    bool badTolerance=false;
    try { (void)Encode(exact_bf,sizeof(exact_bf),false,
                       std::numeric_limits<float>::quiet_NaN(),true); }
    catch(const std::invalid_argument&) { badTolerance=true; }
    assert(badTolerance);
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
