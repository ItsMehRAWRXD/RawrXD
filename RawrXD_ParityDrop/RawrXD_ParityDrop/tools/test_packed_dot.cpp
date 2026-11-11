// Compiles with C++17 and the standard library only:
//   c++ -std=c++17 -O2 -Wall -Wextra -pedantic tools/test_packed_dot.cpp -o test_packed_dot
#include "../src/modelgenie/RawrXDParityPackedDot.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>
using namespace RawrXDParityPackedDot;
static float expectedQ4(const Q4K& q, const Q8K& y) {
    double result=0;
    for (int group=0; group<8; ++group) {
        int sc=0,mn=0; K4ScaleMin(q.scales,group,sc,mn);
        for (int i=0; i<32; ++i) {
            int v=group%2 ? q.qs[(group/2)*32+i]>>4 : q.qs[(group/2)*32+i]&15;
            float w=(HalfToFloat(q.d)*float(sc)*float(v) - HalfToFloat(q.dmin)*float(mn));
            result += double(w) * double(y.d * float(y.qs[group*32+i]));
        }
    }
    return float(result);
}
static float expectedQ6(const Q6K& q, const Q8K& y) {
    double result=0;
    for (int group=0;group<8;++group) {
        int half=group/4,part=group%4;
        for(int i=0;i<32;++i) {
            int lo=(q.ql[half*64+(part&1)*32+i]>>(part>=2?4:0))&15;
            int hi=(q.qh[half*32+i]>>(2*part))&3;
            int w=(lo|(hi<<4))-32;
            int sc=q.scales[group*2+i/16];
            float weight=HalfToFloat(q.d)*float(sc)*float(w);
            result += double(weight)*double(y.d*float(y.qs[group*32+i]));
        }
    }
    return float(result);
}
int main() {
    assert(HalfToFloat(0x3c00)==1.0f);
    assert(HalfToFloat(0xbc00)==-1.0f);
    assert(HalfToFloat(0)==0.0f);
    assert(std::fabs(HalfToFloat(0x0001)-5.960464477539063e-8f)<1.e-15f);
    const float sample[] = {1.0f, -1.0f, 0.5f, 0.0f};
    std::vector<float> v(512);
    for(int i=0;i<512;++i) v[i]=sample[i%4]*(1.0f+float(i%11)/11.0f);
    std::vector<Q8K> q8;
    assert(QuantizeQ8K(v.data(),v.size(),q8));
    assert(q8.size()==2);
    for (auto& q : q8) {
        for (int i=0;i<16;++i) {
            int sum=0;for(int j=0;j<16;++j)sum+=q.qs[i*16+j];
            assert(sum==q.bsums[i]);
        }
    }
    // Seeded deterministic synthetic blocks, including all 6-bit scale/min
    // packing combinations. This is a math test, not GGUF reference parity.
    std::vector<Q4K> w4(4);std::vector<Q6K> w6(4);
    uint32_t seed=0x81fdab23;
    auto rnd=[&seed](){ seed=seed*1664525u+1013904223u;return seed; };
    for(int b=0;b<4;++b){
        w4[b].d=0x2c00;w4[b].dmin=0x2000;
        w6[b].d=0x2c00;
        for(auto &a:w4[b].scales) a=uint8_t(rnd()>>24);
        for(auto &a:w4[b].qs) a=uint8_t(rnd()>>24);
        for(auto &a:w6[b].ql) a=uint8_t(rnd()>>24);
        for(auto &a:w6[b].qh) a=uint8_t(rnd()>>24);
        for(auto &a:w6[b].scales) a=int8_t((rnd()>>24)-128);
    }
    for(int b=0;b<4;++b){
        const float p4=DotQ4(reinterpret_cast<const uint8_t*>(&w4[b]),q8.data()+b%2,1);
        const float e4=expectedQ4(w4[b],q8[b%2]);
        const float p6=DotQ6(reinterpret_cast<const uint8_t*>(&w6[b]),q8.data()+b%2,1);
        const float e6=expectedQ6(w6[b],q8[b%2]);
        assert(std::isfinite(p4)&&std::isfinite(p6));
        assert(std::fabs(p4-e4)<=.0002f*std::max(1.0f,std::fabs(e4)));
        assert(std::fabs(p6-e6)<=.0002f*std::max(1.0f,std::fabs(e6)));
    }
    std::vector<Q4K> mq4(4);std::vector<Q6K> mq6(4);
    std::memcpy(mq4.data(),w4.data(),sizeof(w4[0])*4);
    std::memcpy(mq6.data(),w6.data(),sizeof(w6[0])*4);
    float o4[2]={},o6[2]={};
    assert(MatVec(Kind::Q4_K,mq4.data(),sizeof(Q4K)*4,512,2,v.data(),o4));
    assert(MatVec(Kind::Q6_K,mq6.data(),sizeof(Q6K)*4,512,2,v.data(),o6));
    for(int row=0;row<2;++row){
        float x4=DotQ4(reinterpret_cast<const uint8_t*>(mq4.data()+2*row),q8.data(),2);
        float x6=DotQ6(reinterpret_cast<const uint8_t*>(mq6.data()+2*row),q8.data(),2);
        assert(o4[row]==x4 && o6[row]==x6);
    }
    assert(!MatVec(Kind::Q4_K,mq4.data(),sizeof(Q4K)*3,512,2,v.data(),o4));
    assert(!MatVec(Kind::Q6_K,mq6.data(),sizeof(Q6K)*4,513,2,v.data(),o6));
    std::cout<<"PACKED_DOT_SELFTEST=PASS Q4_K=PASS Q6_K=PASS VALIDATION=PASS\n";
}
