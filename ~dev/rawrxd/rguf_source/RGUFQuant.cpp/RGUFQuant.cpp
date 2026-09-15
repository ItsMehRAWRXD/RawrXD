#include "RGUFQuant.hpp"
#include <algorithm>
#include <cmath>
#include <cstring>
namespace rguf {
bool quantize_q4(const float* x,size_t n,std::vector<uint8_t>& out){out.clear();size_t groups=(n+31)/32;out.resize(groups*(4+16),0);for(size_t g=0;g<groups;g++){size_t base=g*32,m=std::min<size_t>(32,n-base);float mx=0;for(size_t i=0;i<m;i++)mx=std::max(mx,std::fabs(x[base+i]));float scale=mx/7.0f;if(scale==0)scale=1.0f;std::memcpy(out.data()+g*20,&scale,4);for(size_t i=0;i<32;i++){int q=0;if(i<m){q=(int)std::lrint(x[base+i]/scale);q=std::max(-8,std::min(7,q));}uint8_t nib=(uint8_t)(q<0?q+16:q);if((i&1)==0)out[g*20+4+i/2]=nib;else out[g*20+4+i/2]|=(uint8_t)(nib<<4);}}return true;}
bool dequantize_q4(const uint8_t* p,size_t bytes,size_t n,std::vector<float>& out){size_t groups=(n+31)/32;if(bytes<groups*20)return false;out.resize(n);for(size_t g=0;g<groups;g++){float scale;std::memcpy(&scale,p+g*20,4);for(size_t i=0;i<32&&g*32+i<n;i++){uint8_t z=p[g*20+4+i/2];int q=(i&1)?(z>>4):(z&15);if(q>=8)q-=16;out[g*32+i]=q*scale;}}return true;}
}
