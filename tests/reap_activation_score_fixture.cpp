#include <cstdint>
#include <fstream>
#include <limits>
#include <string>
#include <vector>
namespace {
template<class T> void put(std::ofstream& o,T v) { o.write(reinterpret_cast<const char*>(&v),sizeof(v)); }
void route(std::ofstream& o,uint32_t id) {
    put(o,uint32_t{3});put(o,uint64_t{2});put(o,uint32_t{2});put(o,uint32_t{2});
    put(o,uint32_t{0});put(o,id);put(o,0.75f);put(o,0.25f);put(o,2.0f);put(o,3.0f);
}
void observation(std::ofstream& o,uint32_t kind,uint32_t id,float weight,float x,float y,uint64_t step=2) {
    put(o,uint32_t{3});put(o,step);put(o,kind);put(o,id);put(o,weight);put(o,uint32_t{2});put(o,x);put(o,y);
}
}
int main(int argc,char** argv) {
    if(argc!=4)return 2;
    const std::string mode=argv[1];
    const std::vector<std::string> known={"ranking","repeat","reorder","truncated","missing","extra","wrong_step","wrong_weight","duplicate","nan","missing_route","bad_expert","duplicate_route_id"};
    bool valid=false;for(const auto& x:known)valid|=x==mode;if(!valid)return 2;
    std::ofstream r(argv[2],std::ios::binary|std::ios::trunc),o(argv[3],std::ios::binary|std::ios::trunc);
    if(!r||!o)return 2;
    for(int i=0;i<(mode=="repeat"?2:1);++i) {
        route(r,mode=="bad_expert"?8u:mode=="duplicate_route_id"?0u:1u);
        observation(o,0,UINT32_MAX,1.0f,0.0f,0.0f);
        if(mode=="reorder")observation(o,1,1,0.25f,0.0f,20.0f);
        observation(o,1,0,0.75f,1.0f,0.0f);
        if(mode=="duplicate")observation(o,1,0,0.75f,1.0f,0.0f);
        else if(mode=="truncated")put(o,uint32_t{3});
        else if(mode!="reorder"&&mode!="missing")observation(o,1,1,mode=="wrong_weight"?0.5f:0.25f,0.0f,mode=="nan"?std::numeric_limits<float>::quiet_NaN():20.0f,mode=="wrong_step"?3u:2u);
        if(mode=="extra")observation(o,1,1,0.25f,0.0f,20.0f);
    }
    r.close();o.close();return r&&o?0:2;
}
