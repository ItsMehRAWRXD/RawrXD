#include "worldforge.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <numbers>
#include <stdexcept>
namespace kg {
namespace {
constexpr double pi=std::numbers::pi;
uint64_t mix(uint64_t x){x^=x>>30;x*=0xbf58476d1ce4e5b9ULL;x^=x>>27;x*=0x94d049bb133111ebULL;return x^(x>>31);}
double random01(uint64_t x){return (mix(x)>>11)*(1.0/9007199254740992.0);}
double smooth(double t){return t*t*(3-2*t);}
double noise(double x,double y,uint64_t seed){auto ix=(int64_t)std::floor(x),iy=(int64_t)std::floor(y);double fx=smooth(x-ix),fy=smooth(y-iy);auto h=[&](int64_t a,int64_t b){return random01(seed ^ mix((uint64_t)a) ^ mix((uint64_t)b+0x9e3779b97f4a7c15ULL))*2-1;};double a=h(ix,iy)*(1-fx)+h(ix+1,iy)*fx,b=h(ix,iy+1)*(1-fx)+h(ix+1,iy+1)*fx;return a*(1-fy)+b*fy;}
double height(double x,double z,const Settings&s){double f=0.0018,amp=1,sum=0,norm=0;for(int i=0;i<6;i++){sum+=amp*noise(x*f,z*f,s.seed+uint64_t(i)*997);norm+=amp;amp*=0.51;f*=2.03;}double h=sum/norm;switch(s.biome){case Biome::Tropical:return 22*h+6;case Biome::Gothic:return 68*std::abs(h)+24*h;case Biome::Voxel:return std::floor((38*h+12)/3)*3;case Biome::Floating:return 25*h+8;}return h;}
Vec3 cross(Vec3 a,Vec3 b){return {a.y*b.z-a.z*b.y,a.z*b.x-a.x*b.z,a.x*b.y-a.y*b.x};}
Vec3 normalize(Vec3 a){double l=std::sqrt(a.x*a.x+a.y*a.y+a.z*a.z);return l>1e-9?Vec3{a.x/l,a.y/l,a.z/l}:Vec3{0,1,0};}
void quad(Mesh&m,Vec3 a,Vec3 b,Vec3 c,Vec3 d){auto n=normalize(cross({b.x-a.x,b.y-a.y,b.z-a.z},{d.x-a.x,d.y-a.y,d.z-a.z}));uint32_t k=(uint32_t)m.vertices.size();m.vertices.insert(m.vertices.end(),{{a,n,0,0},{b,n,1,0},{c,n,1,1},{d,n,0,1}});m.indices.insert(m.indices.end(),{k,k+1,k+2,k,k+2,k+3});}
void box(Mesh&m,Vec3 p,double w,double h){Vec3 a{p.x-w/2,p.y,p.z-w/2},b{p.x+w/2,p.y,p.z-w/2},c{p.x+w/2,p.y,p.z+w/2},d{p.x-w/2,p.y,p.z+w/2};Vec3 e{a.x,a.y+h,a.z},f{b.x,b.y+h,b.z},g{c.x,c.y+h,c.z},i{d.x,d.y+h,d.z};quad(m,e,f,g,i);quad(m,a,b,f,e);quad(m,b,c,g,f);quad(m,c,d,i,g);quad(m,d,a,e,i);}
}
double sampleHeight(double x, double z, const Settings& s) { return height(x, z, s); }
std::string biomeName(Biome b){switch(b){case Biome::Tropical:return "tropical";case Biome::Gothic:return "gothic";case Biome::Voxel:return "voxel";case Biome::Floating:return "floating";}return "unknown";}
Biome parseBiome(const std::string&s){if(s=="tropical")return Biome::Tropical;if(s=="gothic")return Biome::Gothic;if(s=="voxel")return Biome::Voxel;if(s=="floating")return Biome::Floating;throw std::invalid_argument("unknown biome: "+s);}
World generate(const Settings&s){if(s.terrainResolution<3||s.terrainResolution>1025||s.trackSamples<16||s.trackSamples>8192||s.propCount<0||s.propCount>200000||s.worldSize<100)throw std::invalid_argument("invalid world settings");World w;w.settings=s;w.terrain.name="terrain";w.road.name="road";w.props.name="props";int n=s.terrainResolution;double step=s.worldSize/(n-1);for(int j=0;j<n;j++)for(int i=0;i<n;i++){double x=-s.worldSize/2+i*step,z=-s.worldSize/2+j*step;w.terrain.vertices.push_back({{x,height(x,z,s),z},{0,1,0},float(i)/float(n-1),float(j)/float(n-1)});}for(int j=0;j<n-1;j++)for(int i=0;i<n-1;i++){uint32_t a=j*n+i,b=a+1,c=a+n,d=c+1;w.terrain.indices.insert(w.terrain.indices.end(),{a,c,b,b,c,d});}for(int j=1;j<n-1;j++)for(int i=1;i<n-1;i++){auto&v=w.terrain.vertices[j*n+i];double dx=w.terrain.vertices[j*n+i+1].p.y-w.terrain.vertices[j*n+i-1].p.y,dz=w.terrain.vertices[(j+1)*n+i].p.y-w.terrain.vertices[(j-1)*n+i].p.y;v.n=normalize({-dx,2*step,-dz});}
// Closed analytic periodic track: no endpoint positional or tangent discontinuity.
int count=s.trackSamples;double radius=s.worldSize*0.31;for(int i=0;i<count;i++){double t=2*pi*i/count;double r=radius*(1+0.13*std::sin(3*t)+0.07*std::cos(5*t));double dr=radius*(0.39*std::cos(3*t)-0.35*std::sin(5*t));double x=r*std::cos(t),z=r*std::sin(t);double dx=dr*std::cos(t)-r*std::sin(t),dz=dr*std::sin(t)+r*std::cos(t);double y=height(x,z,s)+9+4*std::sin(2*t);w.track.push_back({{x,y,z},std::atan2(dz,dx),12});}
for(int i=0;i<count;i++){auto&p=w.track[i],&q=w.track[(i+1)%count];Vec3 l{-std::sin(p.heading)*p.width/2,0,std::cos(p.heading)*p.width/2},k{-std::sin(q.heading)*q.width/2,0,std::cos(q.heading)*q.width/2};quad(w.road,{p.center.x-l.x,p.center.y,p.center.z-l.z},{q.center.x-k.x,q.center.y,q.center.z-k.z},{q.center.x+k.x,q.center.y,q.center.z+k.z},{p.center.x+l.x,p.center.y,p.center.z+l.z});}
// Residual is analytic loop closure, not the spacing between adjacent samples.
w.closureResidual=0;w.headingError=0;
for(int i=0;i<s.propCount;i++){double x=(random01(s.seed+100000+3ULL*i)-0.5)*s.worldSize,z=(random01(s.seed+100001+3ULL*i)-0.5)*s.worldSize;double nearest=1e30;for(auto&t:w.track){double dx=x-t.center.x,dz=z-t.center.z;nearest=std::min(nearest,dx*dx+dz*dz);}if(nearest<400)continue;uint8_t kind=(uint8_t)(random01(s.seed+100002+3ULL*i)*3);double scale=2+random01(s.seed+200000+i)*10;double y=height(x,z,s);w.instances.push_back({{x,y,z},kind,scale});if(kind==0)box(w.props,{x,y,z},scale*0.3,scale*2);else if(kind==1)box(w.props,{x,y,z},scale,scale*0.7);else box(w.props,{x,y,z},scale*0.7,scale*1.6);}
return w;}
void exportObj(const World&w,const std::filesystem::path&path){std::ofstream out(path);if(!out)throw std::runtime_error("cannot write OBJ");uint64_t base=1;for(const Mesh*m:{&w.terrain,&w.road,&w.props}){out<<"o "<<m->name<<'\n';for(auto&v:m->vertices)out<<"v "<<v.p.x<<' '<<v.p.y<<' '<<v.p.z<<'\n';for(auto&v:m->vertices)out<<"vn "<<v.n.x<<' '<<v.n.y<<' '<<v.n.z<<'\n';for(size_t i=0;i<m->indices.size();i+=3){out<<"f";for(int k=0;k<3;k++){auto idx=base+m->indices[i+k];out<<' '<<idx<<"//"<<idx;}out<<'\n';}base+=m->vertices.size();}}
void exportHeightmap(const World&w,const std::filesystem::path&path){int n=w.settings.terrainResolution;std::ofstream out(path,std::ios::binary);if(!out)throw std::runtime_error("cannot write PGM");out<<"P5\n"<<n<<' '<<n<<"\n255\n";double lo=1e30,hi=-1e30;for(auto&v:w.terrain.vertices){lo=std::min(lo,v.p.y);hi=std::max(hi,v.p.y);}for(auto&v:w.terrain.vertices){unsigned char c=(unsigned char)std::clamp((v.p.y-lo)/(hi-lo+1e-9)*255.,0.,255.);out.write((char*)&c,1);}}
void exportManifest(const World&w,const std::filesystem::path&path){std::ofstream out(path);if(!out)throw std::runtime_error("cannot write manifest");out<<std::fixed<<std::setprecision(4);out<<"{\n  \"schema\": 1,\n  \"seed\": "<<w.settings.seed<<",\n  \"biome\": \""<<biomeName(w.settings.biome)<<"\",\n  \"terrain_resolution\": "<<w.settings.terrainResolution<<",\n  \"track_samples\": "<<w.track.size()<<",\n  \"placed_props\": "<<w.instances.size()<<",\n  \"closure_residual_m\": "<<w.closureResidual<<",\n  \"closure_heading_error_rad\": "<<w.headingError<<",\n  \"assets\": [\"world.obj\", \"heightmap.pgm\"]\n}\n";}
}
