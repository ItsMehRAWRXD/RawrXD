#pragma once
// Independent, native GGML-compatible Q2_K through Q6_K and Q8_K block codec.
// Wire layout follows ggml-common.h, NOT the legacy custom TensorView K layouts.
// Two-pass GGUF writer uses the same encoder for preflight and emission.
#include "NativeTensorCompression.hpp"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace RawrXD { namespace NativeKQuant {
using RawrXD::TensorCompression::Float;
using RawrXD::TensorCompression::FromHalf;
using RawrXD::TensorCompression::ToHalf;

inline size_t BlockBytes(uint32_t type) {
    switch(type) {
        case 10: return 84;   // Q2_K: scales16, qs64, d2, dmin2
        case 11: return 110;  // Q3_K: hmask32, qs64, scales12, d2
        case 12: return 144;  // Q4_K: d2, dmin2, scales12, qs128
        case 13: return 176;  // Q5_K: d2, dmin2, scales12, qh32, qs128
        case 14: return 210;  // Q6_K: ql128, qh64, scales16, d2
        case 15: return 292;  // Q8_K: d4, qs256, bsums[16]
        default: return 0;
    }
}
inline uint16_t Half(const uint8_t* p) {
    return uint16_t(p[0]) | (uint16_t(p[1])<<8);
}
inline void SetHalf(uint8_t* p, uint16_t v) {
    p[0]=uint8_t(v); p[1]=uint8_t(v>>8);
}
inline int RoundClamp(double x,int lo,int hi) {
    if (x<=lo) return lo;
    if (x>=hi) return hi;
    return int(std::round(x));
}
// Decode using GGML's actual byte ordering. No guessed bitstream packing.
inline bool DecodeBlock(uint32_t type,const uint8_t* b,double v[256]) {
    if(!b || !v || !BlockBytes(type))return false;
    if(type==15) {
        uint32_t bits=uint32_t(b[0])|(uint32_t(b[1])<<8)|
                      (uint32_t(b[2])<<16)|(uint32_t(b[3])<<24);
        const double d=double(Float(bits));
        if(!std::isfinite(d))return false;
        for(int j=0;j<256;++j)v[j]=d*int8_t(b[4+j]);
        return true;
    }
    if(type==10) {
        const double d=FromHalf(Half(b+80)), dm=FromHalf(Half(b+82));
        for(int j=0;j<256;++j) {
            const int g=j/16;
            const unsigned sc=b[g]&15, mn=b[g]>>4;
            const unsigned q=(b[16+(g/8)*32+((g%8)%2)*16+(j%16)]>>(2*((g%8)/2)))&3;
            v[j]=d*sc*q-dm*mn;
        }
        return true;
    }
    if(type==11) {
        const double d=FromHalf(Half(b+108));
        for(int j=0;j<256;++j) {
            const int g=j/16;
            const unsigned code=(g<8)?(b[96+g]&15):(b[96+g-8]>>4);
            const unsigned hi=(b[104+(g%4)]>>(2*(g/4)))&3;
            const int sc=int(code|(hi<<4))-32;
            const int lane=(j%128)/32;
            const unsigned low=(b[32+(j/128)*32+(j%32)]>>(2*lane))&3;
            const bool high=(b[j%32] & (1u<<(j/32)))!=0;
            v[j]=d*sc*(int(low)-(high?0:4));
        }
        return true;
    }
    if(type==12 || type==13) {
        const double d=FromHalf(Half(b)), m=FromHalf(Half(b+2));
        const uint8_t* scale=b+4;
        const uint8_t* high=type==13?b+16:nullptr;
        const uint8_t* low=type==13?b+48:b+16;
        for(int j=0;j<256;++j) {
            const int g=j/32;
            const int is=g<4?int(scale[g]&63):int((scale[g+4]&15)|((scale[g-4]>>6)<<4));
            const int im=g<4?int(scale[g+4]&63):int((scale[g+4]>>4)|((scale[g]>>6)<<4));
            const int packed=low[(g/2)*32+j%32];
            int q=(g%2)?(packed>>4):(packed&15);
            if(high && (high[j%32] & (1u<<(2*(g/2)+(g%2)))))q+=16;
            v[j]=d*is*q-m*im;
        }
        return true;
    }
    const double d=FromHalf(Half(b+208));
    for(int j=0;j<256;++j) {
        const int group=j/16, chunk=j/128, lane=(j%128)/32;
        const int column=j%32;
        const int loIndex=chunk*64+(lane/2)*32+column;
        const unsigned lo=(b[loIndex]>>((lane%2)*4))&15;
        const unsigned hi=(b[128+chunk*32+column]>>(lane*2))&3;
        const int q=int(lo|(hi<<4))-32;
        v[j]=d*int(int8_t(b[192+group]))*q;
    }
    return true;
}
inline bool ReadFloatingBlock(const uint8_t* raw,uint32_t type,double v[256]) {
    if(!raw || !v)return false;
    if(type!=0 && type!=1 && type!=28 && type!=30)return false;
    for(int j=0;j<256;++j) {
        if(type==28) {
            uint64_t bits=0;
            for(int k=0;k<8;++k)bits|=uint64_t(raw[j*8+k])<<(8*k);
            std::memcpy(&v[j],&bits,8);
        } else if(type==0) {
            uint32_t bits=0;
            for(int k=0;k<4;++k)bits|=uint32_t(raw[j*4+k])<<(8*k);
            v[j]=Float(bits);
        } else {
            const uint16_t h=Half(raw+j*2);
            v[j]=type==1?FromHalf(h):Float(uint32_t(h)<<16);
        }
        if(!std::isfinite(v[j]))return false;
    }
    return true;
}
inline bool EncodeBlock(uint32_t type,const double v[256],float tolerance,uint8_t* out) {
    const size_t bytes=BlockBytes(type);
    if(!bytes || !out || !v || !std::isfinite(tolerance) || tolerance<0)return false;
    for(int j=0;j<256;++j)if(!std::isfinite(v[j]))return false;
    std::memset(out,0,bytes);
    if(type==15) {
        double maxAbs=0;
        for(int j=0;j<256;++j)maxAbs=std::max(maxAbs,std::fabs(v[j]));
        const float d=float(maxAbs/127.0);
        if(!std::isfinite(d)||(maxAbs>0&&d<=0))return false;
        uint32_t bits=0;std::memcpy(&bits,&d,4);
        for(int k=0;k<4;++k)out[k]=uint8_t(bits>>(8*k));
        int16_t sums[16]={};
        for(int j=0;j<256;++j) {
            const int q=d?RoundClamp(v[j]/double(d),-127,127):0;
            out[4+j]=uint8_t(int8_t(q));
            sums[j/16]=int16_t(sums[j/16]+q);
            if(!(std::fabs(double(d)*q-v[j])<=double(tolerance)))return false;
        }
        for(int j=0;j<16;++j) {
            const uint16_t sum=uint16_t(sums[j]);
            out[260+2*j]=uint8_t(sum);
            out[261+2*j]=uint8_t(sum>>8);
        }
    } else if(type==10) {
        double scale[16]={},minimum[16]={},maxScale=0,maxMinimum=0;
        for(int g=0;g<16;++g) {
            double lo=v[g*16],hi=lo;
            for(int k=1;k<16;++k) {
                lo=std::min(lo,v[g*16+k]);
                hi=std::max(hi,v[g*16+k]);
            }
            scale[g]=std::max(0.0,(hi-std::max(0.0,lo))/3.0);
            minimum[g]=std::max(0.0,-lo);
            maxScale=std::max(maxScale,scale[g]);
            maxMinimum=std::max(maxMinimum,minimum[g]);
        }
        const uint16_t hd=ToHalf(float(maxScale/15.0));
        const uint16_t hm=ToHalf(float(maxMinimum/15.0));
        const double d=FromHalf(hd),dm=FromHalf(hm);
        if((maxScale>0 && !(d>0)) || (maxMinimum>0 && !(dm>0)))return false;
        SetHalf(out+80,hd);SetHalf(out+82,hm);
        for(int g=0;g<16;++g) {
            const int sc=d>0?RoundClamp(scale[g]/d,0,15):0;
            const int mn=dm>0?RoundClamp(minimum[g]/dm,0,15):0;
            out[g]=uint8_t(sc|(mn<<4));
            const double ds=d*sc, ms=dm*mn;
            for(int k=0;k<16;++k) {
                const int j=g*16+k;
                const int q=ds>0?RoundClamp((v[j]+ms)/ds,0,3):0;
                out[16+(g/8)*32+((g%8)%2)*16+k]|=uint8_t(q<<(2*((g%8)/2)));
            }
        }
    } else if(type==11 || type==14) {
        constexpr int groups=16;
        const int levels=type==11?31:127;
        const int divisor=type==11?31:127;
        double local[groups]={},peak=0;
        for(int g=0;g<groups;++g) {
            double neg=0,pos=0;
            for(int k=0;k<16;++k) {
                const double z=v[g*16+k];
                pos=std::max(pos,z);
                neg=std::max(neg,-z);
            }
            local[g]=std::max(pos/(type==11?3.0:31.0),
                              neg/(type==11?4.0:32.0));
            peak=std::max(peak,local[g]);
        }
        const uint16_t half=ToHalf(float(peak/double(divisor)));
        const double d=FromHalf(half);
        if(!std::isfinite(d) || (peak>0 && d<=0))return false;
        SetHalf(out+(type==11?108:208),half);
        for(int g=0;g<groups;++g) {
            const int sc=d>0?RoundClamp(local[g]/d,0,levels):0;
            const double scale=d*sc;
            if(type==11) {
                const unsigned code=unsigned(sc+32);
                if(g<8)out[96+g]|=uint8_t(code&15);
                else out[96+g-8]|=uint8_t((code&15)<<4);
                out[104+g%4]|=uint8_t(((code>>4)&3)<<(2*(g/4)));
            } else out[192+g]=uint8_t(int8_t(sc));
            for(int k=0;k<16;++k) {
                const int j=g*16+k;
                const int q=scale>0?RoundClamp(v[j]/scale,
                            type==11?-4:-32,type==11?3:31):0;
                const int code=q+(type==11?4:32);
                const int chunk=j/128,lane=(j%128)/32,col=j%32;
                if(type==11) {
                    out[32+chunk*32+col]|=uint8_t((code&3)<<(2*lane));
                    if(code&4)out[j%32]|=uint8_t(1u<<(j/32));
                } else {
                    out[chunk*64+(lane/2)*32+col]|=uint8_t((code&15)<<((lane%2)*4));
                    out[128+chunk*32+col]|=uint8_t(((code>>4)&3)<<(2*lane));
                }
            }
        }
    } else {
        const int levels=type==12?15:31;
        double scales[8]={},mins[8]={},maxScale=0,maxMin=0;
        for(int g=0;g<8;++g) {
            double lo=v[g*32],hi=lo;
            for(int k=1;k<32;++k) {
                lo=std::min(lo,v[g*32+k]);
                hi=std::max(hi,v[g*32+k]);
            }
            mins[g]=std::max(0.0,-lo);
            scales[g]=std::max(0.0,(hi+mins[g])/double(levels));
            maxScale=std::max(maxScale,scales[g]);
            maxMin=std::max(maxMin,mins[g]);
        }
        const uint16_t hd=ToHalf(float(maxScale/63.0)),hm=ToHalf(float(maxMin/63.0));
        const double d=FromHalf(hd),m=FromHalf(hm);
        if(!std::isfinite(d)||!std::isfinite(m)||
           (maxScale>0 && d<=0)||(maxMin>0 && m<=0))return false;
        SetHalf(out,hd);SetHalf(out+2,hm);
        for(int g=0;g<8;++g) {
            const int sc=d>0?RoundClamp(scales[g]/d,0,63):0;
            const int mn=m>0?RoundClamp(mins[g]/m,0,63):0;
            if(g<4){out[4+g]|=uint8_t(sc);out[8+g]|=uint8_t(mn);}
            else {
                out[4+g+4]|=uint8_t((sc&15)|((mn&15)<<4));
                out[4+g-4]|=uint8_t((sc>>4)<<6);
                out[4+g]|=uint8_t((mn>>4)<<6);
            }
            const double scale=d*sc,minimum=m*mn;
            for(int k=0;k<32;++k) {
                const int j=g*32+k;
                const int q=scale>0?RoundClamp((v[j]+minimum)/scale,0,levels):0;
                const int byteIndex=(g/2)*32+k;
                const int lowOffset=type==12?16:48;
                out[lowOffset+byteIndex]|=uint8_t((q&15)<<((g%2)*4));
                if(type==13 && (q&16))
                    out[16+k]|=uint8_t(1u<<(2*(g/2)+(g%2)));
            }
        }
    }
    double reconstructed[256];
    if(!DecodeBlock(type,out,reconstructed))return false;
    for(int j=0;j<256;++j)
        if(!std::isfinite(reconstructed[j]) ||
           !(std::fabs(reconstructed[j]-v[j])<=double(tolerance)))return false;
    return true;
}
}} // namespace RawrXD::NativeKQuant
