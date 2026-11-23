#include "../src/core/NativeGGUFBlockDecoders.hpp"
#include <cassert>
#include <cstdint>
using namespace RawrXD::Compression;
int main() {
    uint8_t q4[18] = {0x00,0x3c};
    for (int i=0;i<16;++i) q4[2+i] = uint8_t((i << 4) | (15-i));
    GGUFDecoderContext c4{GGUFBlockFormat::Q4_0};
    float out[4];
    assert(decodeGGUFBlockSlice(q4,sizeof q4,128,0,sizeof out,reinterpret_cast<uint8_t*>(out),&c4));
    assert(out[0] == 7.f && out[1] == 6.f && out[2] == 5.f && out[3] == 4.f);
    assert(decodeGGUFBlockSlice(q4,sizeof q4,128,16*4,sizeof out,reinterpret_cast<uint8_t*>(out),&c4));
    assert(out[0] == -8.f && out[1] == -7.f && out[2] == -6.f && out[3] == -5.f);
    uint8_t q8[34] = {0x00,0x38};
    for(int i=0;i<32;++i) q8[2+i] = static_cast<uint8_t>(static_cast<int8_t>(i-16));
    GGUFDecoderContext c8{GGUFBlockFormat::Q8_0};
    assert(decodeGGUFBlockSlice(q8,sizeof q8,128,15*4,sizeof out,reinterpret_cast<uint8_t*>(out),&c8));
    assert(out[0]==-0.5f && out[1]==0.f && out[2]==0.5f && out[3]==1.f);
    assert(!decodeGGUFBlockSlice(q8,sizeof q8,128,1,4,reinterpret_cast<uint8_t*>(out),&c8));
    assert(!decodeGGUFBlockSlice(q8,33,128,0,4,reinterpret_cast<uint8_t*>(out),&c8));
}
