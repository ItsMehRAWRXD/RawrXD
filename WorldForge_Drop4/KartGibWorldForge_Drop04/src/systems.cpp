#include "systems.hpp"
#include <algorithm>
#include <cmath>
#include <fstream>
#include <limits>
#include <map>
#include <numbers>
#include <stdexcept>
namespace kg::systems {
namespace {
Vec3 sub(Vec3 a,Vec3 b){return {a.x-b.x,a.y-b.y,a.z-b.z};}
Vec3 add(Vec3 a,Vec3 b){return {a.x+b.x,a.y+b.y,a.z+b.z};}
Vec3 mul(Vec3 a,double k){return {a.x*k,a.y*k,a.z*k};}
double dot(Vec3 a,Vec3 b){return a.x*b.x+a.y*b.y+a.z*b.z;}
Vec3 cross(Vec3 a,Vec3 b){return {a.y*b.z-a.z*b.y,a.z*b.x-a.x*b.z,a.x*b.y-a.y*b.x};}
double norm(Vec3 a){return std::sqrt(dot(a,a));}
Vec3 unit(Vec3 a){double n=norm(a);return n>1e-12?mul(a,1/n):Vec3{0,1,0};}
bool finite(Vec3 p){return std::isfinite(p.x)&&std::isfinite(p.y)&&std::isfinite(p.z);}
uint64_t hash(uint64_t x){x^=x>>30;x*=0xbf58476d1ce4e5b9ULL;x^=x>>27;x*=0x94d049bb133111ebULL;return x^(x>>31);}
double rand01(uint64_t x){return (hash(x)>>11)*(1./9007199254740992.);}
}
bool validateMesh(const Mesh&m){if(m.indices.size()%3)return false;for(auto&v:m.vertices)if(!finite(v.p)||!finite(v.n)||!std::isfinite(v.u)||!std::isfinite(v.v))return false;for(auto i:m.indices)if(i>=m.vertices.size())return false;return true;}
Bounds bounds(const Mesh&m){if(m.vertices.empty())return {};auto lo=m.vertices[0].p,hi=lo;for(auto&v:m.vertices){lo.x=std::min(lo.x,v.p.x);lo.y=std::min(lo.y,v.p.y);lo.z=std::min(lo.z,v.p.z);hi.x=std::max(hi.x,v.p.x);hi.y=std::max(hi.y,v.p.y);hi.z=std::max(hi.z,v.p.z);}return {lo,hi};}
void recalculateNormals(Mesh&m){if(!validateMesh(m))throw std::invalid_argument("invalid mesh");for(auto&v:m.vertices)v.n={0,0,0};for(size_t i=0;i<m.indices.size();i+=3){auto a=m.indices[i],b=m.indices[i+1],c=m.indices[i+2];Vec3 n=cross(sub(m.vertices[b].p,m.vertices[a].p),sub(m.vertices[c].p,m.vertices[a].p));for(auto idx:{a,b,c})m.vertices[idx].n=add(m.vertices[idx].n,n);}for(auto&v:m.vertices)v.n=unit(v.n);}
size_t triangleCount(const World&w){return (w.terrain.indices.size()+w.road.indices.size()+w.props.indices.size())/3;}
Hit raycast(const Mesh&m,Ray r,double maxDistance){Hit best;best.distance=maxDistance;if(!validateMesh(m)||!finite(r.origin)||!finite(r.direction)||maxDistance<=0)return best;for(size_t i=0;i<m.indices.size();i+=3){auto a=m.vertices[m.indices[i]].p,b=m.vertices[m.indices[i+1]].p,c=m.vertices[m.indices[i+2]].p;auto e1=sub(b,a),e2=sub(c,a),p=cross(r.direction,e2);double det=dot(e1,p);if(std::abs(det)<1e-12)continue;double inv=1/det;auto t=sub(r.origin,a);double u=dot(t,p)*inv;if(u<0||u>1)continue;double v=dot(r.direction,cross(t,e1))*inv;if(v<0||u+v>1)continue;double d=dot(e2,cross(t,e1))*inv;if(d>=0&&d<best.distance){best={true,d,add(r.origin,mul(r.direction,d))};}}return best;}
double sampleTerrain(const World&w,double x,double z){int n=w.settings.terrainResolution;if(n<2||w.terrain.vertices.size()!=size_t(n)*n)throw std::invalid_argument("terrain grid invalid");double half=w.settings.worldSize*.5,step=w.settings.worldSize/(n-1);double fx=std::clamp((x+half)/step,0.,double(n-1)),fz=std::clamp((z+half)/step,0.,double(n-1));int ix=std::min(int(fx),n-2),iz=std::min(int(fz),n-2);double tx=fx-ix,tz=fz-iz;auto h=[&](int a,int b){return w.terrain.vertices[size_t(b)*n+a].p.y;};return (h(ix,iz)*(1-tx)+h(ix+1,iz)*tx)*(1-tz)+(h(ix,iz+1)*(1-tx)+h(ix+1,iz+1)*tx)*tz;}
std::vector<Checkpoint> checkpoints(const World&w,int count){if(count<1||count>int(w.track.size()))throw std::invalid_argument("checkpoint count invalid");std::vector<Checkpoint> result;for(int i=0;i<count;i++){auto&t=w.track[size_t(i)*w.track.size()/count];result.push_back({t.center,t.width*.7});}return result;}
size_t nearestTrackPoint(const World&w,Vec3 p){if(w.track.empty())throw std::invalid_argument("track empty");size_t best=0;double dist=std::numeric_limits<double>::infinity();for(size_t i=0;i<w.track.size();++i){auto d=sub(w.track[i].center,p);double q=dot(d,d);if(q<dist){dist=q;best=i;}}return best;}
double lapProgress(const World&w,Vec3 p){return double(nearestTrackPoint(w,p))/w.track.size();}
Weather weather(uint64_t seed,double timeSeconds){double t=std::floor(std::max(0.,timeSeconds)/300.);uint64_t k=uint64_t(t);return {rand01(seed^hash(k+11)),rand01(seed^hash(k+23))*.75,rand01(seed^hash(k+37))*.65,rand01(seed^hash(k+53))*20};}
Sun sunlight(double hour){double a=(hour-6)*std::numbers::pi/12;double elev=std::sin(a),az=std::cos(a);return {unit({az,-elev,.3}),std::max(0.,elev)*5.};}
Camera chaseCamera(Vec3 p,double heading,double speed){double back=7+std::clamp(speed,0.,100.)*.035;Vec3 f{std::cos(heading),0,std::sin(heading)};return {add(sub(p,mul(f,back)),{0,3.5,0}),add(p,mul(f,12)),std::clamp(65+speed*.13,65.,85.)};}
int chooseLod(double distance,double bias){if(distance<0||bias<=0)throw std::invalid_argument("LOD input invalid");double d=distance*bias;return d<40?0:d<120?1:d<300?2:3;}
std::vector<Cell> buildPropGrid(const World&w,double cellSize){if(cellSize<=0||!std::isfinite(cellSize))throw std::invalid_argument("cell size invalid");std::map<std::pair<int,int>,Cell> cells;for(uint32_t i=0;i<w.instances.size();++i){auto&p=w.instances[i].position;int x=int(std::floor(p.x/cellSize)),z=int(std::floor(p.z/cellSize));auto&cell=cells[{x,z}];cell.x=x;cell.z=z;cell.propIndices.push_back(i);}std::vector<Cell> out;for(auto&entry:cells)out.push_back(std::move(entry.second));return out;}
Quality assess(const World&w,double maximumGrade){Quality q;q.minimumWidth=std::numeric_limits<double>::infinity();if(!validateMesh(w.terrain)||!validateMesh(w.road)||!validateMesh(w.props)){q.reason="INVALID_MESH";return q;}if(w.track.size()<16){q.reason="INSUFFICIENT_TRACK";return q;}for(size_t i=0;i<w.track.size();i++){auto&a=w.track[i],&b=w.track[(i+1)%w.track.size()];auto d=sub(a.center,b.center);double flat=std::hypot(d.x,d.z);if(flat<1e-8){q.reason="ZERO_LENGTH_SEGMENT";return q;}q.maximumGrade=std::max(q.maximumGrade,std::abs(d.y)/flat);q.minimumWidth=std::min(q.minimumWidth,a.width);}if(q.maximumGrade>maximumGrade){q.reason="TRACK_GRADE_EXCEEDED";return q;}if(q.minimumWidth<3){q.reason="TRACK_TOO_NARROW";return q;}q.pass=true;q.reason="PASS";return q;}
std::array<Material,4> biomeMaterials(Biome b){switch(b){case Biome::Tropical:return {{{"sand",.95,0,0},{"foliage",.9,0,0},{"asphalt",.82,0,0},{"boost",.25,.4,5}}};case Biome::Gothic:return {{{"stone",.88,0,0},{"moss",.95,0,0},{"road",.8,0,0},{"torch",.4,0,4}}};case Biome::Voxel:return {{{"grass",1,0,0},{"dirt",1,0,0},{"stone",1,0,0},{"water",.2,0,0}}};case Biome::Floating:return {{{"rock",.9,0,0},{"grass",.95,0,0},{"cloud",1,0,0},{"crystal",.15,.2,3}}};}return {};}
void exportSceneReport(const World&w,const std::filesystem::path&path){std::ofstream f(path);if(!f)throw std::runtime_error("cannot write scene report");auto q=assess(w);auto b=bounds(w.terrain);f<<"{\n  \"schema\": 2,\n  \"triangles\": "<<triangleCount(w)<<",\n  \"quality_pass\": "<<(q.pass?"true":"false")<<",\n  \"quality_reason\": \""<<q.reason<<"\",\n  \"maximum_track_grade\": "<<q.maximumGrade<<",\n  \"terrain_min_y\": "<<b.lo.y<<",\n  \"terrain_max_y\": "<<b.hi.y<<",\n  \"prop_grid_cells\": "<<buildPropGrid(w,64).size()<<"\n}\n";}
}
