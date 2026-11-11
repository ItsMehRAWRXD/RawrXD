#include "editor/tools.hpp"
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <limits>
#include <cctype>
namespace worldforge::editor::tools {
namespace fs=std::filesystem;
static bool finite(Vec3 v){return std::isfinite(v.x)&&std::isfinite(v.y)&&std::isfinite(v.z);}
static Vec3 add(Vec3 a,Vec3 b){return {a.x+b.x,a.y+b.y,a.z+b.z};}
static Vec3 sub(Vec3 a,Vec3 b){return {a.x-b.x,a.y-b.y,a.z-b.z};}
static Vec3 mul(Vec3 a,double s){return {a.x*s,a.y*s,a.z*s};}
static double dot(Vec3 a,Vec3 b){return a.x*b.x+a.y*b.y+a.z*b.z;}
static Vec3 cross(Vec3 a,Vec3 b){return {a.y*b.z-a.z*b.y,a.z*b.x-a.x*b.z,a.x*b.y-a.y*b.x};}
static Vec3 norm(Vec3 v){double n=std::sqrt(dot(v,v));return n>1e-12?mul(v,1/n):Vec3{};}
bool safeRelativePath(const std::string& path){if(path.empty()||path.find('\\')!=std::string::npos)return false;fs::path p(path);if(p.is_absolute()||p.has_root_name())return false;for(auto& part:p)if(part=="..")return false;return true;}
bool AssetBrowser::scan(const std::string& root){std::error_code ec;auto base=fs::weakly_canonical(root,ec);if(ec||!fs::is_directory(base))return false;std::vector<Asset> next;fs::recursive_directory_iterator it(base,fs::directory_options::skip_permission_denied,ec),end;for(;!ec&&it!=end;++it){if(it.depth()>12){it.disable_recursion_pending();continue;}if(it->is_symlink(ec)){if(it->is_directory(ec))it.disable_recursion_pending();continue;}if(!it->is_regular_file(ec))continue;auto rel=it->path().lexically_relative(base).generic_string();if(!safeRelativePath(rel))continue;auto ext=it->path().extension().string();std::transform(ext.begin(),ext.end(),ext.begin(),[](unsigned char c){return (char)std::tolower(c);});std::string kind=(ext==".obj"?"mesh":ext==".png"||ext==".ppm"?"texture":ext==".wfs"?"scene":"other");next.push_back({rel,kind,it->file_size(ec)});if(next.size()>=10000)break;}if(ec)return false;std::sort(next.begin(),next.end(),[](const Asset&a,const Asset&b){return a.path<b.path;});items=std::move(next);return true;}
std::vector<Asset> AssetBrowser::filter(const std::string& q)const{std::vector<Asset> r;for(auto& a:items)if(a.path.find(q)!=std::string::npos||a.kind.find(q)!=std::string::npos)r.push_back(a);return r;}
Mat4 identity(){Mat4 a;for(int i=0;i<4;i++)a.m[i*4+i]=1;return a;}
Mat4 multiply(const Mat4&a,const Mat4&b){Mat4 c;for(int r=0;r<4;r++)for(int k=0;k<4;k++)for(int col=0;col<4;col++)c.m[r*4+col]+=a.m[r*4+k]*b.m[k*4+col];return c;}
Mat4 transformMatrix(Transform t){auto [x,y,z]=t.rotation;double cx=cos(x),sx=sin(x),cy=cos(y),sy=sin(y),cz=cos(z),sz=sin(z);Mat4 a=identity();a.m[0]=(cz*cy)*t.scale.x;a.m[1]=(cz*sy*sx-sz*cx)*t.scale.y;a.m[2]=(cz*sy*cx+sz*sx)*t.scale.z;a.m[4]=(sz*cy)*t.scale.x;a.m[5]=(sz*sy*sx+cz*cx)*t.scale.y;a.m[6]=(sz*sy*cx-cz*sx)*t.scale.z;a.m[8]=-sy*t.scale.x;a.m[9]=cy*sx*t.scale.y;a.m[10]=cy*cx*t.scale.z;a.m[3]=t.position.x;a.m[7]=t.position.y;a.m[11]=t.position.z;return a;}
Vec3 transformPoint(const Mat4&a,Vec3 p){return {a.m[0]*p.x+a.m[1]*p.y+a.m[2]*p.z+a.m[3],a.m[4]*p.x+a.m[5]*p.y+a.m[6]*p.z+a.m[7],a.m[8]*p.x+a.m[9]*p.y+a.m[10]*p.z+a.m[11]};}
std::optional<Mat4> inverseAffine(const Mat4&a){double det=a.m[0]*(a.m[5]*a.m[10]-a.m[6]*a.m[9])-a.m[1]*(a.m[4]*a.m[10]-a.m[6]*a.m[8])+a.m[2]*(a.m[4]*a.m[9]-a.m[5]*a.m[8]);if(!std::isfinite(det)||fabs(det)<1e-12)return {};Mat4 b=identity();b.m[0]=(a.m[5]*a.m[10]-a.m[6]*a.m[9])/det;b.m[1]=(a.m[2]*a.m[9]-a.m[1]*a.m[10])/det;b.m[2]=(a.m[1]*a.m[6]-a.m[2]*a.m[5])/det;b.m[4]=(a.m[6]*a.m[8]-a.m[4]*a.m[10])/det;b.m[5]=(a.m[0]*a.m[10]-a.m[2]*a.m[8])/det;b.m[6]=(a.m[2]*a.m[4]-a.m[0]*a.m[6])/det;b.m[8]=(a.m[4]*a.m[9]-a.m[5]*a.m[8])/det;b.m[9]=(a.m[1]*a.m[8]-a.m[0]*a.m[9])/det;b.m[10]=(a.m[0]*a.m[5]-a.m[1]*a.m[4])/det;for(int i=0;i<3;i++)b.m[i*4+3]=-(b.m[i*4]*a.m[3]+b.m[i*4+1]*a.m[7]+b.m[i*4+2]*a.m[11]);return b;}
ScreenRay viewportRay(double px,double py,double w,double h,const Camera& c){if(w<=0||h<=0||c.fov<=0||c.fov>=179||!std::isfinite(px)||!std::isfinite(py))return {};Vec3 f=norm(sub(c.target,c.eye));if(dot(f,f)<0.5)return {};Vec3 right=norm(cross(f,{0,1,0}));if(dot(right,right)<0.5)right=norm(cross(f,{0,0,1}));Vec3 up=norm(cross(right,f));double v=tan(c.fov*3.141592653589793/360.0);Vec3 d=norm(add(f,add(mul(right,(2*px/w-1)*(w/h)*v),mul(up,(1-2*py/h)*v))));return {{c.eye,d},true};}
std::optional<double> rayPlane(Ray ray,Vec3 p,Vec3 n){double d=dot(ray.direction,n);if(fabs(d)<1e-10)return {};double t=dot(sub(p,ray.origin),n)/d;if(!std::isfinite(t)||t<0)return {};return t;}
Vec3 snap(Vec3 v,double s){if(!(s>0)||!std::isfinite(s))return v;return {std::round(v.x/s)*s,std::round(v.y/s)*s,std::round(v.z/s)*s};}
static const Node* node(const Scene& s,Id id){for(auto& n:s.nodes())if(n.id==id)return &n;return nullptr;}
bool applyTranslation(Scene& s,Id id,Vec3 delta,double step){auto n=node(s,id);if(!n||n->locked||!finite(delta))return false;Transform t=n->local;t.position=snap(add(t.position,delta),step);return s.setTransform(id,t);}
bool applyScale(Scene& s,Id id,Vec3 factor,double step){auto n=node(s,id);if(!n||n->locked||!finite(factor))return false;Transform t=n->local;t.scale=snap({t.scale.x*factor.x,t.scale.y*factor.y,t.scale.z*factor.z},step);if(t.scale.x<=0||t.scale.y<=0||t.scale.z<=0)return false;return s.setTransform(id,t);}
bool applyRotation(Scene& s,Id id,Vec3 rad,double step){auto n=node(s,id);if(!n||n->locked||!finite(rad))return false;Transform t=n->local;t.rotation=snap(add(t.rotation,rad),step);return s.setTransform(id,t);}
std::optional<Inspector> inspect(const Scene& s,Id id){auto n=node(s,id);if(!n)return {};return Inspector{n->id,n->name,n->local,n->visible,n->locked};}
}
