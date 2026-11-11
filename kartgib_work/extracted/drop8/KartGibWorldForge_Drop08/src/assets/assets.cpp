#include "assets/assets.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <limits>
#include <stdexcept>
#include <string>
namespace kg::assets {
namespace {
constexpr double pi=3.14159265358979323846;
Vec3 v(double x,double y,double z){return {x,y,z};}
void tri(Mesh& m,Vec3 a,Vec3 b,Vec3 c){auto cross=[](Vec3 x,Vec3 y){return v(x.y*y.z-x.z*y.y,x.z*y.x-x.x*y.z,x.x*y.y-x.y*y.x);};auto e1=v(b.x-a.x,b.y-a.y,b.z-a.z),e2=v(c.x-a.x,c.y-a.y,c.z-a.z);auto n=cross(e1,e2);double l=std::sqrt(n.x*n.x+n.y*n.y+n.z*n.z);if(l>1e-12){n.x/=l;n.y/=l;n.z/=l;}uint32_t k=static_cast<uint32_t>(m.vertices.size());m.vertices.push_back({a,n,0,0});m.vertices.push_back({b,n,1,0});m.vertices.push_back({c,n,0,1});m.indices.insert(m.indices.end(),{k,k+1,k+2});}
void quad(Mesh& m,Vec3 a,Vec3 b,Vec3 c,Vec3 d){tri(m,a,b,c);tri(m,a,c,d);}
void addBox(Mesh& m,double w,double h,double d,Vec3 o){auto x=w*.5,z=d*.5;Vec3 a=v(o.x-x,o.y,o.z-z),b=v(o.x+x,o.y,o.z-z),c=v(o.x+x,o.y+h,o.z-z),e=v(o.x-x,o.y+h,o.z-z);Vec3 f=v(o.x-x,o.y,o.z+z),g=v(o.x+x,o.y,o.z+z),i=v(o.x+x,o.y+h,o.z+z),j=v(o.x-x,o.y+h,o.z+z);quad(m,f,g,i,j);quad(m,b,a,e,c);quad(m,a,f,j,e);quad(m,g,b,c,i);quad(m,e,j,i,c);quad(m,a,b,g,f);}
}
uint64_t hash(uint64_t x){x+=0x9e3779b97f4a7c15ULL;x=(x^(x>>30))*0xbf58476d1ce4e5b9ULL;x=(x^(x>>27))*0x94d049bb133111ebULL;return x^(x>>31);}
double random01(uint64_t x){return static_cast<double>(hash(x)>>11)*(1.0/9007199254740992.0);}
Mesh box(double w,double h,double d){if(w<=0||h<=0||d<=0)throw std::invalid_argument("box dimensions");Mesh m;m.name="box";addBox(m,w,h,d,{});return m;}
Mesh cylinder(double r,double h,int sides){if(r<=0||h<=0||sides<3||sides>256)throw std::invalid_argument("cylinder geometry");Mesh m;m.name="cylinder";for(int i=0;i<sides;i++){double a=2*pi*i/sides,b=2*pi*(i+1)/sides;Vec3 p=v(r*std::cos(a),0,r*std::sin(a)),q=v(r*std::cos(b),0,r*std::sin(b)),s=v(q.x,h,q.z),t=v(p.x,h,p.z);quad(m,p,q,s,t);tri(m,v(0,h,0),t,s);tri(m,v(0,0,0),q,p);}return m;}
Mesh cone(double r,double h,int sides){if(r<=0||h<=0||sides<3||sides>256)throw std::invalid_argument("cone geometry");Mesh m;m.name="cone";for(int i=0;i<sides;i++){double a=2*pi*i/sides,b=2*pi*(i+1)/sides;auto p=v(r*std::cos(a),0,r*std::sin(a)),q=v(r*std::cos(b),0,r*std::sin(b));tri(m,p,q,v(0,h,0));tri(m,v(0,0,0),q,p);}return m;}
void translate(Mesh& m,Vec3 o){for(auto& p:m.vertices){p.p.x+=o.x;p.p.y+=o.y;p.p.z+=o.z;}}
void merge(Mesh& dst,const Mesh& src,Vec3 o){if(src.vertices.size()>UINT32_MAX-dst.vertices.size())throw std::overflow_error("mesh index overflow");uint32_t base=static_cast<uint32_t>(dst.vertices.size());for(auto p:src.vertices){p.p.x+=o.x;p.p.y+=o.y;p.p.z+=o.z;dst.vertices.push_back(p);}for(uint32_t idx:src.indices)dst.indices.push_back(base+idx);}
Mesh tree(uint64_t seed,int branches){if(branches<1||branches>64)throw std::invalid_argument("tree branches");Mesh m;m.name="tree";double h=5+random01(seed)*5;merge(m,cylinder(.27,h,7),{});for(int i=0;i<branches;i++){double a=2*pi*i/branches;double y=h*(.35+.45*random01(seed+i+1));double reach=1.5+random01(seed+i+99)*2;auto leaf=cone(.6+reach*.35,2.3,6);merge(m,leaf,v(std::cos(a)*reach*.55,y,std::sin(a)*reach*.55));}return m;}
Mesh palm(uint64_t seed){Mesh m;m.name="palm";double h=7+3*random01(seed);merge(m,cylinder(.22,h,8),{});for(int i=0;i<9;i++){double a=2*pi*i/9,reach=3+random01(seed+i)*2;Mesh leaf;tri(leaf,v(0,h,0),v(std::cos(a)*reach,h-.8,std::sin(a)*reach),v(std::cos(a+.25)*reach*.65,h-.4,std::sin(a+.25)*reach*.65));merge(m,leaf,{});}return m;}
Mesh rock(uint64_t seed){Mesh m;m.name="rock";double r=1+random01(seed)*2;auto c=cone(r,1.3*r,7);merge(m,c,{});return m;}
Mesh house(uint64_t seed){Mesh m;m.name="house";double w=5+random01(seed)*3;addBox(m,w,4,w*.8,{});merge(m,cone(w*.75,3,4),v(0,4,0));return m;}
Mesh tower(uint64_t seed){Mesh m;m.name="tower";double h=12+random01(seed)*9;merge(m,cylinder(2,h,10),{});merge(m,cone(3,5,10),v(0,h,0));return m;}
Mesh bridge(uint64_t seed){Mesh m;m.name="bridge";double length=14+random01(seed)*8;addBox(m,5,.8,length,v(0,5,0));for(int z=-1;z<=1;z+=2){addBox(m,.6,5,.6,v(-2,0,z*(length*.45)));addBox(m,.6,5,.6,v(2,0,z*(length*.45)));}return m;}
Mesh arch(uint64_t seed){Mesh m;m.name="arch";double h=5+random01(seed)*2;addBox(m,1,h,1,v(-3,0,0));addBox(m,1,h,1,v(3,0,0));addBox(m,7,1.4,1,v(0,h,0));return m;}
Mesh fence(uint64_t seed){Mesh m;m.name="fence";int count=4+static_cast<int>(random01(seed)*5);for(int i=0;i<count;i++)addBox(m,.25,2,.25,v(i*1.5,0,0));addBox(m,(count-1)*1.5+.4,.2,.2,v((count-1)*.75,1.25,0));return m;}
Bounds bounds(const Mesh& mesh){if(mesh.vertices.empty())throw std::invalid_argument("empty mesh");Bounds b{mesh.vertices[0].p,mesh.vertices[0].p};for(const auto& p:mesh.vertices){b.min.x=std::min(b.min.x,p.p.x);b.min.y=std::min(b.min.y,p.p.y);b.min.z=std::min(b.min.z,p.p.z);b.max.x=std::max(b.max.x,p.p.x);b.max.y=std::max(b.max.y,p.p.y);b.max.z=std::max(b.max.z,p.p.z);}return b;}
Catalog generate(uint64_t seed,Biome biome,int count){if(count<0||count>100000)throw std::invalid_argument("placement count");Catalog c;c.meshes={tree(seed),palm(seed),rock(seed),house(seed),tower(seed),bridge(seed),arch(seed),fence(seed)};for(int i=0;i<count;i++){uint64_t s=hash(seed+static_cast<uint64_t>(i)*3);uint32_t kind=static_cast<uint32_t>(s%8);if(biome==Biome::Tropical&&kind==0)kind=1;if(biome==Biome::Gothic&&kind==1)kind=4;if(biome==Biome::Voxel&&kind==1)kind=3;c.placements.push_back({kind,v((random01(s+1)-.5)*600,0,(random01(s+2)-.5)*600),random01(s+3)*2*pi,.65+random01(s+4)*.7});}return c;}
void exportObj(const Catalog& c,const std::filesystem::path& path){std::ofstream out(path);if(!out)throw std::runtime_error("cannot write obj");out<<std::setprecision(9);size_t base=1;for(const auto& m:c.meshes){out<<"o "<<m.name<<'\n';for(const auto& vert:m.vertices)out<<"v "<<vert.p.x<<' '<<vert.p.y<<' '<<vert.p.z<<'\n';for(size_t i=0;i+2<m.indices.size();i+=3)out<<"f "<<base+m.indices[i]<<' '<<base+m.indices[i+1]<<' '<<base+m.indices[i+2]<<'\n';base+=m.vertices.size();}if(!out)throw std::runtime_error("obj write failed");}
void exportManifest(const Catalog& c,const std::filesystem::path& path){std::ofstream out(path);if(!out)throw std::runtime_error("cannot write manifest");out<<std::setprecision(12)<<"{\n  \"mesh_count\": "<<c.meshes.size()<<",\n  \"placement_count\": "<<c.placements.size()<<",\n  \"placements\": [\n";for(size_t i=0;i<c.placements.size();i++){auto&p=c.placements[i];out<<"    {\"asset\":"<<p.asset<<",\"position\":["<<p.position.x<<','<<p.position.y<<','<<p.position.z<<"],\"yaw\":"<<p.yaw<<",\"scale\":"<<p.scale<<"}"<<(i+1<c.placements.size()?",":"")<<'\n';}out<<"  ]\n}\n";if(!out)throw std::runtime_error("manifest write failed");}
}
