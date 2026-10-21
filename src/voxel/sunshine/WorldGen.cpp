#include "WorldGen.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <utility>

namespace RawrXD {
namespace Voxel {


namespace sunshine {
namespace {
constexpr double clamp(double v,double a,double b) noexcept { return v<a?a:(v>b?b:v); }
constexpr double smooth(double v) noexcept { return v*v*(3.0-2.0*v); }
std::uint64_t mix(std::uint64_t x) noexcept { x+=0x9e3779b97f4a7c15ULL; x=(x^(x>>30))*0xbf58476d1ce4e5b9ULL; x=(x^(x>>27))*0x94d049bb133111ebULL; return x^(x>>31); }
int floorInt(double x) noexcept { return static_cast<int>(std::floor(x)); }
int floorDiv(int a,int b) noexcept { int q=a/b,r=a%b; return r<0?q-1:q; }
std::uint32_t crc32(const std::vector<std::uint8_t>& v,std::size_t n) noexcept {
 std::uint32_t c=~0u; for(std::size_t i=0;i<n;++i){ c^=v[i]; for(int j=0;j<8;++j)c=(c>>1)^(0xedb88320u & (0u-(c&1u))); } return ~c;
}
void put(std::vector<std::uint8_t>& v,std::uint64_t x,int bytes) { for(int i=0;i<bytes;++i)v.push_back(static_cast<std::uint8_t>(x>>(8*i))); }
std::uint64_t get(const std::vector<std::uint8_t>& v,std::size_t& p,int bytes) {
 if(p+static_cast<std::size_t>(bytes)>v.size())throw std::runtime_error("truncated worldgen file");
 std::uint64_t x=0; for(int i=0;i<bytes;++i)x|=std::uint64_t(v[p++])<<(8*i); return x;
}
void finish(std::vector<std::uint8_t>& v){ put(v,crc32(v,v.size()),4); }
void check(const std::vector<std::uint8_t>& v,const char* magic){
 if(v.size()<12 || !std::equal(magic,magic+4,v.begin()))throw std::runtime_error("bad worldgen magic");
 std::size_t p=v.size()-4; auto expected=static_cast<std::uint32_t>(get(v,p,4));
 if(expected!=crc32(v,v.size()-4))throw std::runtime_error("worldgen checksum mismatch");
}
}
bool Config::valid() const noexcept {
 if(world!="islands" || scale<1 || scale>64 || sea<0 || sea>1024)return false;
 for(int v:{mountains,erosion,caves,trees,temperature,humidity,rivers,structures})if(v<0 || v>100)return false;
 return true;
}
Block Chunk::at(int x,int y,int z) const noexcept { return blocks[static_cast<std::size_t>((y*ChunkSize+z)*ChunkSize+x)]; }
void Chunk::set(int x,int y,int z,Block b) noexcept { blocks[static_cast<std::size_t>((y*ChunkSize+z)*ChunkSize+x)]=b; }
Generator::Generator(Config cfg):cfg_(std::move(cfg)){ if(!cfg_.valid())throw std::invalid_argument("invalid Sunshine world config"); }
std::uint64_t Generator::hash(int x,int y,int z,std::uint64_t salt) const noexcept {
 auto h=mix(cfg_.seed^salt); h=mix(h^static_cast<std::uint32_t>(x)); h=mix(h^static_cast<std::uint32_t>(y)); return mix(h^static_cast<std::uint32_t>(z));
}
double Generator::noise(double x,double z,std::uint64_t salt) const noexcept {
 const int ix=floorInt(x),iz=floorInt(z); const double fx=smooth(x-ix),fz=smooth(z-iz);
 auto val=[&](int a,int b){ return static_cast<double>(hash(a,0,b,salt)>>11)*0x1.0p-53; };
 const double a=val(ix,iz)*(1-fx)+val(ix+1,iz)*fx;
 const double b=val(ix,iz+1)*(1-fx)+val(ix+1,iz+1)*fx;
 return a*(1-fz)+b*fz;
}
double Generator::fractal(double x,double z,std::uint64_t salt,int octaves) const noexcept {
 double s=0,w=0,amp=1; for(int i=0;i<octaves;++i){s+=amp*noise(x,z,salt+static_cast<std::uint64_t>(i)*101);w+=amp;amp*=0.5;x*=2;z*=2;}return s/w;
}
double Generator::islandMask(int x,int z) const noexcept {
 // Broad, overlapping archipelago fields; not a single island at origin.
 const double sc=static_cast<double>(cfg_.scale), fx=x/(280.0*sc),fz=z/(280.0*sc);
 const double warp=(fractal(x/(410.0*sc),z/(410.0*sc),11,3)-0.5)*1.8;
 const double d=std::sqrt((fx+warp*0.25)*(fx+warp*0.25)+(fz-warp*0.25)*(fz-warp*0.25));
 const double mainland=clamp((1.25-d)/0.65,0.0,1.0);
 const double scattered=fractal(x/(165.0*sc),z/(165.0*sc),21,4);
 return clamp(std::max(mainland,clamp((scattered-0.48)*3.5,0.0,0.85)),0.0,1.0);
}
double Generator::riverValue(int x,int z) const noexcept {
 const double sc=static_cast<double>(cfg_.scale);
 const double warp=(noise(x/(150.0*sc),z/(150.0*sc),31)-0.5)*42.0*sc;
 return std::abs(noise((x+warp)/(100.0*sc),(z-warp)/(100.0*sc),32)-0.5);
}
int Generator::height(int x,int z) const noexcept {
 const double sc=static_cast<double>(cfg_.scale), mask=islandMask(x,z);
 const double broad=(fractal(x/(115.0*sc),z/(115.0*sc),41,5)-0.5)*24;
 const double ridge=1.0-std::abs(2*fractal(x/(62.0*sc),z/(62.0*sc),42,4)-1.0);
 const double peaks=std::pow(ridge,3.0)*cfg_.mountains*0.9;
 const double fine=(fractal(x/(14.0*sc),z/(14.0*sc),43,3)-0.5)*8*(1.0-cfg_.erosion/130.0);
 double h=cfg_.sea-13+mask*(24+broad+peaks+fine);
 const double river=riverValue(x,z), width=0.008+cfg_.rivers*0.00020;
 if(cfg_.rivers && river<width)h-=((width-river)/width)*(2.0+cfg_.rivers*0.075)*mask;
 return static_cast<int>(std::floor(h));
}
Block Generator::terrain(int x,int y,int z) const noexcept {
 if(y<0)return Block::Stone;
 const int h=height(x,z);
 if(y>h)return y<=cfg_.sea?Block::Water:Block::Air;
 if(y>4 && y<h-3 && cfg_.caves>0){
   const double sc=static_cast<double>(cfg_.scale);
   const double a=noise((x+y*0.53)/(19.0*sc),(z-y*0.37)/(19.0*sc),51);
   const double b=noise((x-y*0.31)/(13.0*sc),(z+y*0.43)/(13.0*sc),52);
   if(a*0.55+b*0.45>0.81-cfg_.caves*0.0015)return Block::Air;
 }
 if(y<h-4)return Block::Stone;
 const bool beach=h<=cfg_.sea+3;
 if(y==h){if(beach)return Block::Sand;if(h>cfg_.sea+43 && cfg_.temperature<55)return Block::Snow;return Block::Grass;}
 return beach?Block::Sand:Block::Dirt;
}
Block Generator::decoration(int x,int y,int z) const noexcept {
 // Scan deterministic nearby anchors so chunk seams are exact and order independent.
 if(y<=cfg_.sea || y>cfg_.sea+110)return Block::Air;
 const int cell=9*cfg_.scale;
 const int gx=floorDiv(x,cell),gz=floorDiv(z,cell);
 for(int dz=-1;dz<=1;++dz)for(int dx=-1;dx<=1;++dx){
   const int ax=gx+dx,az=gz+dz;
   const int tx=ax*cell+static_cast<int>(hash(ax,0,az,61)%static_cast<std::uint64_t>(cell));
   const int tz=az*cell+static_cast<int>(hash(ax,0,az,62)%static_cast<std::uint64_t>(cell));
   const int th=height(tx,tz);
   if(th<=cfg_.sea+3 || th>cfg_.sea+75)continue;
   const auto chance=hash(ax,0,az,63)%100;
   const bool structure=cfg_.structures>0 && chance<static_cast<std::uint64_t>(cfg_.structures/12);
   const bool tree=!structure && chance<static_cast<std::uint64_t>(cfg_.trees*cfg_.humidity/125);
   const int rx=x-tx,rz=z-tz,ry=y-th;
   if(structure){
     if(std::abs(rx)<=2 && std::abs(rz)<=2 && ry>=1 && ry<=5){
       if(ry==5 || std::abs(rx)==2 || std::abs(rz)==2){
         if(ry<=2 && rz==-2 && rx==0)continue;
         return Block::Brick;
       }
     }
   } else if(tree){
     const int trunk=4+static_cast<int>(hash(ax,0,az,64)%3);
     if(rx==0 && rz==0 && ry>=1 && ry<=trunk)return Block::Wood;
     if(ry>=trunk-2 && ry<=trunk+2 && rx*rx+rz*rz+(ry-trunk)*(ry-trunk)<=8)return Block::Leaves;
   }
 }
 return Block::Air;
}
Block Generator::sample(int x,int y,int z) const noexcept {
 const Block d=decoration(x,y,z);
 return d!=Block::Air?d:terrain(x,y,z);
}
Chunk Generator::generate(int cx,int cy,int cz) const noexcept {
 Chunk c; c.cx=cx;c.cy=cy;c.cz=cz;
 for(int y=0;y<ChunkSize;++y)for(int z=0;z<ChunkSize;++z)for(int x=0;x<ChunkSize;++x)
   c.set(x,y,z,sample(cx*ChunkSize+x,cy*ChunkSize+y,cz*ChunkSize+z));
 return c;
}
std::vector<std::uint8_t> serializeConfig(const Config& c){
 if(!c.valid())throw std::invalid_argument("invalid config");
 std::vector<std::uint8_t> v={'S','W','G','C'};put(v,1,4);put(v,c.seed,8);
 for(int n:{c.scale,c.sea,c.mountains,c.erosion,c.caves,c.trees,c.temperature,c.humidity,c.rivers,c.structures})put(v,static_cast<std::uint32_t>(n),4);
 finish(v);return v;
}
Config deserializeConfig(const std::vector<std::uint8_t>& v){
 check(v,"SWGC");if(v.size()!=60)throw std::runtime_error("config length mismatch");
 std::size_t p=4;if(get(v,p,4)!=1)throw std::runtime_error("unsupported config version");
 Config c;c.seed=get(v,p,8);int* fields[]={&c.scale,&c.sea,&c.mountains,&c.erosion,&c.caves,&c.trees,&c.temperature,&c.humidity,&c.rivers,&c.structures};
 for(auto* f:fields)*f=static_cast<int>(get(v,p,4));if(!c.valid())throw std::runtime_error("invalid config payload");return c;
}
std::vector<std::uint8_t> serializeChunk(const Chunk& c){
 std::vector<std::uint8_t> v={'S','W','G','K'};put(v,1,4);
 for(int n:{c.cx,c.cy,c.cz})put(v,static_cast<std::uint32_t>(n),4);
 for(auto b:c.blocks)put(v,static_cast<std::uint8_t>(b),1);
 finish(v);return v;
}
Chunk deserializeChunk(const std::vector<std::uint8_t>& v){
 check(v,"SWGK");if(v.size()!=4+4+12+4096+4)throw std::runtime_error("chunk length mismatch");
 std::size_t p=4;if(get(v,p,4)!=1)throw std::runtime_error("unsupported chunk version");
 Chunk c;c.cx=static_cast<std::int32_t>(get(v,p,4));c.cy=static_cast<std::int32_t>(get(v,p,4));c.cz=static_cast<std::int32_t>(get(v,p,4));
 for(auto& b:c.blocks){auto n=get(v,p,1);if(n>static_cast<std::uint8_t>(Block::Snow))throw std::runtime_error("invalid block id");b=static_cast<Block>(n);}return c;
}
}
} // namespace Voxel
} // namespace RawrXD
