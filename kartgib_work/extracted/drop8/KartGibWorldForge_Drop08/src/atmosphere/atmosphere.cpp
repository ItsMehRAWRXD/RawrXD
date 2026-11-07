#include "atmosphere/atmosphere.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <limits>
namespace kartgib::atmosphere {
namespace {constexpr float PI=3.14159265358979323846f; Vec3 add(Vec3 a,Vec3 b){return {a.x+b.x,a.y+b.y,a.z+b.z};} Vec3 mul(Vec3 a,float f){return {a.x*f,a.y*f,a.z*f};} Vec3 mix(Vec3 a,Vec3 b,float t){return add(mul(a,1-t),mul(b,t));} float lerp(float a,float b,float t){return a+(b-a)*t;} float smooth(float t){t=saturate(t);return t*t*(3-2*t);} uint32_t scramble(uint32_t v){v^=v>>16;v*=0x7feb352du;v^=v>>15;v*=0x846ca68bu;v^=v>>16;return v;}}
float saturate(float x){return std::clamp(x,0.f,1.f);}
float dot(Vec3 a,Vec3 b){return a.x*b.x+a.y*b.y+a.z*b.z;}
Vec3 normalize(Vec3 v){float len=std::sqrt(dot(v,v));return len>1e-8f?mul(v,1.f/len):Vec3{0,1,0};}
float hash3(int x,int y,int z,uint32_t seed){uint32_t v=seed^scramble(uint32_t(x)*0x9e3779b9u)^scramble(uint32_t(y)*0x85ebca6bu)^scramble(uint32_t(z)*0xc2b2ae35u);return float(scramble(v)&0xffffffu)/16777215.f;}
float noise3(float x,float y,float z,uint32_t seed){int ix=int(std::floor(x)),iy=int(std::floor(y)),iz=int(std::floor(z));float u=smooth(x-ix),v=smooth(y-iy),w=smooth(z-iz);float a[2][2][2];for(int k=0;k<2;k++)for(int j=0;j<2;j++)for(int i=0;i<2;i++)a[k][j][i]=hash3(ix+i,iy+j,iz+k,seed);float b[2][2];for(int k=0;k<2;k++)for(int j=0;j<2;j++)b[k][j]=lerp(a[k][j][0],a[k][j][1],u);return lerp(lerp(b[0][0],b[0][1],v),lerp(b[1][0],b[1][1],v),w);}
float fbm3(float x,float y,float z,uint32_t seed){float sum=0,amp=.5f,norm=0;for(int i=0;i<5;i++){sum+=amp*noise3(x,y,z,seed+uint32_t(i)*31u);norm+=amp;x*=2.03f;y*=2.03f;z*=2.03f;amp*=.5f;}return sum/norm;}
float sunDisc(Vec3 view,Vec3 sun,float angularRadius){float c=dot(normalize(view),normalize(sun));float radius=std::clamp(angularRadius,.001f,.2f);return 1.f-smooth((1.f-c)/(1.f-std::cos(radius)));}
Vec3 skyColor(Vec3 view,SkySettings s){view=normalize(view);float t=saturate(view.y*.65f+.35f);Vec3 horizon{.76f,.68f,.58f},zenith{.08f,.29f,.66f};float haze=saturate((s.turbidity-1.f)/9.f);Vec3 sky=mix(horizon,zenith,std::pow(t,.55f));sky=mix(sky,Vec3{.62f,.63f,.65f},haze*.3f);float glow=std::pow(saturate(dot(view,normalize(s.sunDirection))),24.f);sky=add(sky,mul(Vec3{1.f,.54f,.19f},glow*.7f));return add(sky,mul(Vec3{9.f,6.f,3.f},sunDisc(view,s.sunDirection)*1.5f));}
float cloudDensity(Vec3 p,SkySettings s){float n=fbm3(p.x*s.cloudScale*.03f,p.y*s.cloudScale*.03f,p.z*s.cloudScale*.03f,s.seed);return smooth((n-(.73f-s.cloudCoverage*.55f))/.25f);}
float cloudShadow(Vec3 p,SkySettings s){Vec3 sun=normalize(s.sunDirection);Vec3 sample=add(p,mul(sun,120.f));return 1.f-.7f*cloudDensity(sample,s);}
float fogTransmittance(float distance,float density){return std::exp(-std::max(0.f,distance)*std::max(0.f,density));}
Vec3 applyFog(Vec3 scene,Vec3 fog,float distance,float density){return mix(fog,scene,fogTransmittance(distance,density));}
float waterHeight(float x,float z,float time,uint32_t seed){float phase=hash3(0,0,0,seed)*6.28318f;return .26f*std::sin(x*.23f+z*.12f+time*1.4f+phase)+.12f*std::sin(x*.51f-z*.37f-time*2.1f+phase*.5f)+.045f*std::sin(x*1.7f+z*1.3f+time*3.2f);}
Vec3 waterNormal(float x,float z,float time,uint32_t seed){constexpr float e=.04f;float dx=(waterHeight(x+e,z,time,seed)-waterHeight(x-e,z,time,seed))/(2*e);float dz=(waterHeight(x,z+e,time,seed)-waterHeight(x,z-e,time,seed))/(2*e);return normalize({-dx,1.f,-dz});}
Image renderSky(int width,int height,SkySettings s){if(width<=0||height<=0||width>8192||height>8192)return {};Image image;image.width=width;image.height=height;image.rgb.resize(size_t(width)*height);for(int y=0;y<height;y++)for(int x=0;x<width;x++){float u=(2.f*(x+.5f)/width-1.f)*1.4f,v=(1.f-2.f*(y+.5f)/height);Vec3 ray=normalize({u,v,1.f});Vec3 sky=skyColor(ray,s);if(ray.y>0.f){Vec3 cloudPos=mul(ray,110.f/std::max(.08f,ray.y));float d=cloudDensity(cloudPos,s);sky=mix(sky,Vec3{1.1f,1.08f,1.05f},d*.85f);}image.rgb[size_t(y)*width+x]=sky;}return image;}
bool writePpm(const Image& image,const std::string& path){if(image.width<=0||image.height<=0||image.rgb.size()!=size_t(image.width)*image.height)return false;std::ofstream f(path,std::ios::binary);if(!f)return false;f<<"P6\n"<<image.width<<' '<<image.height<<"\n255\n";for(Vec3 c:image.rgb){for(float v:{c.x,c.y,c.z}){unsigned char byte=static_cast<unsigned char>(std::lround(std::pow(saturate(v/(1.f+std::max(0.f,v))),1.f/2.2f)*255.f));f.write(reinterpret_cast<const char*>(&byte),1);}}return bool(f);}
}
