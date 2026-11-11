#include "hdr.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <limits>
#include <stdexcept>
namespace kg::render {
namespace {
float clean(float v){return std::isfinite(v)?std::max(0.f,v):0.f;}
Rgb add(Rgb a,Rgb b){return {a.r+b.r,a.g+b.g,a.b+b.b};}
Rgb mul(Rgb a,float k){return {a.r*k,a.g*k,a.b*k};}
Rgb sample(const Image& i,uint32_t x,uint32_t y){return i.at(std::min(x,i.width-1),std::min(y,i.height-1));}
float aces(float x){x=clean(x);return std::clamp((x*(2.51f*x+.03f))/(x*(2.43f*x+.59f)+.14f),0.f,1.f);}
}
bool Image::valid() const{return width>0&&height>0&&uint64_t(width)*height==pixels.size();}
Rgb& Image::at(uint32_t x,uint32_t y){if(x>=width||y>=height)throw std::out_of_range("pixel");return pixels[size_t(y)*width+x];}
const Rgb& Image::at(uint32_t x,uint32_t y)const{if(x>=width||y>=height)throw std::out_of_range("pixel");return pixels[size_t(y)*width+x];}
float luminance(Rgb c){return .2126f*clean(c.r)+.7152f*clean(c.g)+.0722f*clean(c.b);}
float exposureScale(Exposure e){return std::exp2(std::clamp(e.ev,-16.f,16.f));}
Rgb applyExposure(Rgb c,Exposure e){return mul({clean(c.r),clean(c.g),clean(c.b)},exposureScale(e));}
Rgb acesToneMap(Rgb c){return {aces(c.r),aces(c.g),aces(c.b)};}
float linearToSrgb(float c){c=std::clamp(clean(c),0.f,1.f);return c<=.0031308f?12.92f*c:1.055f*std::pow(c,1.f/2.4f)-.055f;}
Rgb encodeSrgb(Rgb c){return {linearToSrgb(c.r),linearToSrgb(c.g),linearToSrgb(c.b)};}
Rgb bloomPrefilter(Rgb c,BloomSettings s){float l=luminance(c);float knee=std::max(.0001f,s.knee);float soft=std::clamp(l-s.threshold+knee,0.f,2.f*knee);soft=soft*soft/(4.f*knee);float contribution=std::max(soft,l-s.threshold)/std::max(l,.0001f);return mul({clean(c.r),clean(c.g),clean(c.b)},contribution);}
Image downsample2x(const Image& source){if(!source.valid())throw std::invalid_argument("source");Image o{std::max(1u,(source.width+1)/2),std::max(1u,(source.height+1)/2),{}};o.pixels.resize(size_t(o.width)*o.height);for(uint32_t y=0;y<o.height;++y)for(uint32_t x=0;x<o.width;++x){Rgb a{};for(uint32_t dy=0;dy<2;++dy)for(uint32_t dx=0;dx<2;++dx)a=add(a,sample(source,x*2+dx,y*2+dy));o.at(x,y)=mul(a,.25f);}return o;}
Image upsampleBilinear(const Image& source,uint32_t width,uint32_t height){if(!source.valid()||!width||!height||uint64_t(width)*height>100000000)throw std::invalid_argument("dimensions");Image o{width,height,{}};o.pixels.resize(size_t(width)*height);for(uint32_t y=0;y<height;++y)for(uint32_t x=0;x<width;++x){float sx=(x+.5f)*source.width/width-.5f,sy=(y+.5f)*source.height/height-.5f;int ix=int(std::floor(sx)),iy=int(std::floor(sy));float fx=sx-ix,fy=sy-iy;auto fetch=[&](int xx,int yy){return source.at(uint32_t(std::clamp(xx,0,int(source.width)-1)),uint32_t(std::clamp(yy,0,int(source.height)-1)));};Rgb a=add(mul(fetch(ix,iy),1-fx),mul(fetch(ix+1,iy),fx));Rgb b=add(mul(fetch(ix,iy+1),1-fx),mul(fetch(ix+1,iy+1),fx));o.at(x,y)=add(mul(a,1-fy),mul(b,fy));}return o;}
Image blurSeparable(const Image& source,uint32_t radius){if(!source.valid()||radius>32)throw std::invalid_argument("blur");if(!radius)return source;Image tmp=source,out=source;float norm=1.f/(2*radius+1);for(uint32_t y=0;y<source.height;++y)for(uint32_t x=0;x<source.width;++x){Rgb sum{};for(int d=-int(radius);d<=int(radius);++d)sum=add(sum,source.at(uint32_t(std::clamp(int(x)+d,0,int(source.width)-1)),y));tmp.at(x,y)=mul(sum,norm);}for(uint32_t y=0;y<source.height;++y)for(uint32_t x=0;x<source.width;++x){Rgb sum{};for(int d=-int(radius);d<=int(radius);++d)sum=add(sum,tmp.at(x,uint32_t(std::clamp(int(y)+d,0,int(source.height)-1))));out.at(x,y)=mul(sum,norm);}return out;}
Image makeBloom(const Image& source,BloomSettings s){if(!source.valid()||s.radius>32)throw std::invalid_argument("bloom");Image filtered=source;for(auto& p:filtered.pixels)p=bloomPrefilter(p,s);Image low=downsample2x(filtered);return upsampleBilinear(blurSeparable(low,s.radius),source.width,source.height);}
Image composite(const Image& hdr,const Image& bloom,RenderSettings settings){if(!hdr.valid()||!bloom.valid()||hdr.width!=bloom.width||hdr.height!=bloom.height)throw std::invalid_argument("composite");std::string error;if(!validateSettings(settings,&error))throw std::invalid_argument(error);Image out=hdr;for(size_t i=0;i<out.pixels.size();++i){Rgb c=hdr.pixels[i];if(settings.bloomEnabled)c=add(c,mul(bloom.pixels[i],settings.bloom.strength));out.pixels[i]=encodeSrgb(acesToneMap(applyExposure(c,settings.exposure)));}return out;}
FrameMetrics analyze(const Image& hdr){if(!hdr.valid())throw std::invalid_argument("analyze");FrameMetrics m;m.pixels=hdr.pixels.size();double sum=0;for(auto c:hdr.pixels){float l=luminance(c);m.maxLuminance=std::max(m.maxLuminance,l);sum+=l;m.clippedChannels+=(c.r>1)+(c.g>1)+(c.b>1);}m.averageLuminance=float(sum/m.pixels);return m;}
bool validateSettings(RenderSettings s,std::string* error){bool ok=std::isfinite(s.exposure.ev)&&s.exposure.ev>=-16&&s.exposure.ev<=16&&std::isfinite(s.exposure.middleGray)&&s.exposure.middleGray>0&&std::isfinite(s.bloom.threshold)&&s.bloom.threshold>=0&&std::isfinite(s.bloom.knee)&&s.bloom.knee>=0&&std::isfinite(s.bloom.strength)&&s.bloom.strength>=0&&s.bloom.strength<=10&&s.bloom.radius<=32;if(!ok&&error)*error="invalid HDR/bloom settings";return ok;}
std::array<float,4> viewportNormalized(Viewport v,uint32_t width,uint32_t height){if(!width||!height||v.x>=width||v.y>=height||!v.width||!v.height||uint64_t(v.x)+v.width>width||uint64_t(v.y)+v.height>height)throw std::invalid_argument("viewport");return {float(v.x)/width,float(v.y)/height,float(v.width)/width,float(v.height)/height};}
bool writePpm(const Image& image,const std::string& path){if(!image.valid())return false;std::ofstream f(path,std::ios::binary);if(!f)return false;f<<"P6\n"<<image.width<<" "<<image.height<<"\n255\n";for(auto c:image.pixels){auto v=encodeSrgb(c);for(float x:{v.r,v.g,v.b}){unsigned char b=(unsigned char)std::lround(std::clamp(x,0.f,1.f)*255.f);f.write(reinterpret_cast<const char*>(&b),1);}}return bool(f);}
}
