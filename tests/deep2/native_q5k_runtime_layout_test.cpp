#include "../../~dev/rawrxd/src/deep2/NativeQ5KDecode.hpp"
#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <iostream>

static void putHalf(uint8_t* p,uint16_t v){p[0]=uint8_t(v);p[1]=uint8_t(v>>8);}
int main(){
    std::array<uint8_t,176> block{};
    putHalf(block.data(),0x3c00); // d = 1
    putHalf(block.data()+2,0x0000); // dmin = 0
    // All eight 6-bit scales are 1; all eight mins are zero.
    for(int i=0;i<4;++i)block[4+i]=1;
    for(int i=0;i<4;++i)block[8+i]=0;
    for(int i=0;i<4;++i)block[12+i]=0x01;
    for(int i=0;i<32;++i){
        block[16+i]=uint8_t((i*37+0xA5)&0xff); // qh: all eight bit planes vary
        block[48+i]=uint8_t((i*29+0xD3)&0xff); // ql: both nibbles vary
        block[80+i]=uint8_t((i*17+0x6B)&0xff);
        block[112+i]=uint8_t((i*11+0x95)&0xff);
    }
    float actual[256]{};
    Deep2::NativeQ5KDequantize(block.data(),actual,256);
    const uint8_t* ql=block.data()+48;
    const uint8_t* qh=block.data()+16;
    uint8_t u1=1,u2=2;
    float expected[256]{};
    for(int j=0;j<256;j+=64){
        for(int l=0;l<32;++l){
            expected[j+l]=float((ql[l]&15u)+((qh[l]&u1)?16u:0u));
            expected[j+32+l]=float((ql[l]>>4)+((qh[l]&u2)?16u:0u));
        }
        ql+=32;u1=uint8_t(u1<<2);u2=uint8_t(u2<<2);
    }
    for(int i=0;i<256;++i)assert(std::fabs(actual[i]-expected[i])==0.0f);
    // Exercise partial output bounds without requiring a padded destination.
    float partial[73]{};
    Deep2::NativeQ5KDequantize(block.data(),partial,73);
    for(int i=0;i<73;++i)assert(partial[i]==expected[i]);
    std::cout<<"Q5_K canonical GGML nibble/high-bit ordering PASS\n";
}
