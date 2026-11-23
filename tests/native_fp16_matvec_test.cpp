#include "../src/core/NativeFP16MatVec.hpp"
#include <cassert>
#include <cstdint>
int main() {
    using namespace RawrXD::Compression;
    // Two rows: [1,2,3,-4], [0.5,-1,0,8]
    const uint8_t weights[] = {
        0x00,0x3c,0x00,0x40,0x00,0x42,0x00,0xc4,
        0x00,0x38,0x00,0xbc,0x00,0x00,0x00,0x48
    };
    const float x[] = {1,2,3,4};
    float y[2] = {};
    assert(fp16MatVec(weights,sizeof weights,2,4,x,y,4));
    assert(y[0]==-2.f && y[1]==30.5f);
    assert(!fp16MatVec(weights,sizeof weights,2,4,x,y,3));
    assert(!fp16MatVec(weights,sizeof weights-1,2,4,x,y,4));
    assert(binary16ToFloat(0x3c00)==1.f);
    assert(binary16ToFloat(0x0001)>0.f);
}
