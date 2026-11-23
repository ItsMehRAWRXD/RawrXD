#include "../../src/deep2/NativeTensorCompression.hpp"
#include <cassert>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cmath>
#include <limits>
#include <algorithm>
using namespace RawrXD::TensorCompression;
int main() {
    const std::vector<uint8_t> repeated(4096,0x5a);
    auto r=Encode(repeated.data(),repeated.size());
    assert(r.encoding==Encoding::RLE && r.payload.size()<repeated.size());
    assert(Decode(r)==repeated);
    std::vector<uint8_t> direct(repeated.size(),0);
    DecodeInto(r,direct.data(),direct.size());
    assert(direct==repeated);
    DecodeInto(raw,direct.data(),randomish.size());
    assert(std::equal(randomish.begin(),randomish.end(),direct.begin()));

    const std::vector<uint8_t> randomish={0,1,2,3,4,5,6,7,8,9};
    auto raw=Encode(randomish.data(),randomish.size());
    assert(raw.encoding==Encoding::Raw && Decode(raw)==randomish);
    const float f[]={1.0f,-2.0f,0.5f,65504.0f};
    auto half=Encode(f,sizeof(f),true,0.0f);
    assert(half.encoding==Encoding::F16 && half.payload.size()==sizeof(f)/2);
    auto decoded=Decode(half);
    assert(std::memcmp(decoded.data(),f,sizeof(f))==0);
    uint8_t directHalf[sizeof(f)]{};
    DecodeInto(half,directHalf,sizeof(directHalf));
    assert(std::memcmp(directHalf,f,sizeof(f))==0);
    // BF16 keeps F32's exponent range when FP16 would overflow.
    const float wide[]={1.0e20f,-1.0e20f,3.25f,-0.0f};
    auto bf16=Encode(wide,sizeof(wide),true,1.0e18f,true);
    assert(bf16.encoding==Encoding::BF16 && bf16.payload.size()==sizeof(wide)/2);
    auto wideDecoded=Decode(bf16);
    uint8_t directBf16[sizeof(wide)]{};
    DecodeInto(bf16,directBf16,sizeof(directBf16));
    assert(std::memcmp(directBf16,wideDecoded.data(),sizeof(wide))==0);
    for(size_t i=0;i<4;++i) {
        float value; std::memcpy(&value,wideDecoded.data()+i*4,4);
        assert(std::isfinite(value));
        assert(std::fabs(value-wide[i])<=1.0e18f);
    }
    assert(ToBFloat16(1.0f)==0x3f80);
    assert(Bits(FromBFloat16(0x3f80))==Bits(1.0f));
    assert(ToBFloat16(-0.0f)==0x8000);
    assert(ToBFloat16(std::numeric_limits<float>::infinity())==0x7f80);
    assert((ToBFloat16(std::numeric_limits<float>::quiet_NaN())&0x7fc0)==0x7fc0);
    // Exhaustively round-trip every finite BF16 bit pattern through F32.
    for(uint32_t h=0;h<65536;++h) {
        if((h&0x7f80u)==0x7f80u) continue;
        assert(ToBFloat16(FromBFloat16(uint16_t(h)))==h);
    }
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
    // Public adaptive API selects one representation for the entire tensor.
    const float adaptiveExact[]={1.0f,-2.0f,0.5f,4.0f};
    auto adaptive=EncodeAdaptiveF32(adaptiveExact,4,0.0f);
    assert(adaptive.encoding==Encoding::F16);
    assert(Decode(adaptive).size()==sizeof(adaptiveExact));
    const float adaptiveWide[]={1.0e20f,-1.0e20f,3.25f,4.0f};
    auto adaptiveBf=EncodeAdaptiveF32(adaptiveWide,4,1.0e18f);
    assert(adaptiveBf.encoding==Encoding::BF16);
    const float adaptiveReject[]={1.0001f,2.0001f};
    auto adaptiveRaw=EncodeAdaptiveF32(adaptiveReject,2,0.0f);
    assert(adaptiveRaw.encoding==Encoding::Raw);
    assert(Decode(adaptiveRaw).size()==sizeof(adaptiveReject));
    bool nullTensor=false;
    try { (void)EncodeAdaptiveF32(nullptr,1,0.1f); }
    catch(const std::invalid_argument&) { nullTensor=true; }
    assert(nullTensor);
    // Chunked residency decodes only the chunks intersecting an inference
    // tile; compressed storage size is measured independently of F32 size.
    std::vector<float> resident(10003);
    for(size_t i=0;i<resident.size();++i)
        resident[i]=(i%7==0)?float(i)*0.25f:float(int(i%19)-9);
    auto chunked=ChunkedF32Storage::Build(resident.data(),resident.size(),0.0f,1024);
    assert(chunked.size()==resident.size() && chunked.chunkCount()==10);
    assert(chunked.chunkElements()==1024);
    assert(chunked.storedBytes()<=resident.size()*sizeof(float));
    std::vector<float> tile(1500,-999.0f);
    chunked.ReadRange(900,tile.size(),tile.data());
    for(size_t i=0;i<tile.size();++i) assert(tile[i]==resident[900+i]);
    std::vector<float> whole(resident.size());
    chunked.ReadRange(0,whole.size(),whole.data());
    assert(whole==resident);
    bool rangeRejected=false;
    try { chunked.ReadRange(resident.size()-1,2,tile.data()); }
    catch(const std::out_of_range&) { rangeRejected=true; }
    assert(rangeRejected);
    bool zeroChunkRejected=false;
    try { (void)ChunkedF32Storage::Build(resident.data(),resident.size(),0.0f,0); }
    catch(const std::invalid_argument&) { zeroChunkRejected=true; }
    assert(zeroChunkRejected);
    const float not_exact[]={1.0001f,2.0001f};
    auto preserved=Encode(not_exact,sizeof(not_exact),true,0.0f);
    assert(preserved.encoding!=Encoding::F16);
    const float specials[]={std::numeric_limits<float>::infinity(),1.0f};
    assert(Encode(specials,sizeof(specials),true,1.0f).encoding!=Encoding::F16);
    assert(ToHalf(1.0f)==0x3c00 && ToHalf(-0.0f)==0x8000);
    assert(Bits(FromHalf(0x3c00))==Bits(1.0f));
    assert(Bits(FromHalf(0x0001))==Bits(0x1p-24f));
    auto malformed=r;
    malformed.payload.push_back(1);
    std::vector<uint8_t> untouched(repeated.size(),0xa5);
    bool malformedRejected=false;
    try { DecodeInto(malformed,untouched.data(),untouched.size()); }
    catch(const std::invalid_argument&) { malformedRejected=true; }
    assert(malformedRejected);
    assert(std::all_of(untouched.begin(),untouched.end(),[](uint8_t x){return x==0xa5;}));
    bool wrongSize=false;
    try { DecodeInto(r,untouched.data(),untouched.size()-1); }
    catch(const std::invalid_argument&) { wrongSize=true; }
    assert(wrongSize);
    bool rejected=false;
    try { auto bad=r; bad.payload[0]=0; (void)Decode(bad); } catch(const std::invalid_argument&) {rejected=true;}
    assert(rejected);
    std::cout<<"native tensor compression tests PASS\n";
}
