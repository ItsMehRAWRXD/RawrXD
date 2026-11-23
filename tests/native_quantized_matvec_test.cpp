#include "../src/core/NativeQuantizedMatVec.hpp"
#include <cassert>
int main() {
    using namespace RawrXD::Compression;
    uint8_t q4[36] = {};
    q4[0]=0; q4[1]=0x3c; q4[18]=0; q4[19]=0x3c;
    for(int i=0;i<16;++i){q4[i+2]=0x99; q4[i+20]=0x77;}
    float x[32]; for(auto &v:x)v=1;
    float y[2] = {};
    assert(quantizedMatVec(q4,sizeof(q4),GGUFBlockFormat::Q4_0,2,32,x,y,128));
    assert(y[0]==32 && y[1]==-32);
    assert(!quantizedMatVec(q4,sizeof(q4)-1,GGUFBlockFormat::Q4_0,2,32,x,y,128));
    uint8_t q8[34] = {}; q8[0]=0; q8[1]=0x3c;
    for(int i=0;i<32;++i) q8[2+i]=2;
    assert(quantizedMatVec(q8,sizeof(q8),GGUFBlockFormat::Q8_0,1,32,x,y,128));
    assert(y[0]==64);
}
