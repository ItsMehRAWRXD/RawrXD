#pragma once
#include "ReapVirtualPayload.hpp"
#include "ReapRetainedRouting.hpp"
#include <cmath>
namespace Deep2 { namespace ReapQuant {
struct ExpertMatrix {
    size_t rows=0,cols=0;
    Precision precision=Precision::Q4;
    BoundedExpertCache::Lease payload;
};
inline bool ExpertMatVec(const ExpertMatrix& m,const std::vector<float>& x,std::vector<float>& out){
    const size_t stride=m.precision==Precision::Q2?Q2Bytes:m.precision==Precision::Q3?Q3Bytes:m.precision==Precision::Q4?Q4Bytes:0;
    if(!stride||!m.payload||!m.rows||!m.cols||m.cols%Elements||x.size()!=m.cols)return false;
    const size_t blocks=m.cols/Elements;
    if(blocks>SIZE_MAX/stride||m.rows>SIZE_MAX/(blocks*stride)||m.payload->size()!=m.rows*blocks*stride)return false;
    std::vector<float> next(m.rows);
    for(size_t r=0;r<m.rows;++r){
        double sum=0;
        for(size_t b=0;b<blocks;++b){
            const auto* p=m.payload->data()+(r*blocks+b)*stride;
            Values v{};
            if(m.precision==Precision::Q2){Q2Block q{};std::memcpy(q.data(),p,stride);if(!DecodeQ2(q,v))return false;}
            else if(m.precision==Precision::Q3){Q3Block q{};std::memcpy(q.data(),p,stride);if(!DecodeQ3(q,v))return false;}
            else {Q4Block q{};std::memcpy(q.data(),p,stride);if(!DecodeQ4(q,v))return false;}
            for(size_t j=0;j<Elements;++j)sum+=double(v[j])*x[b*Elements+j];
        }
        if(!std::isfinite(sum)||std::abs(sum)>std::numeric_limits<float>::max())return false;
        next[r]=float(sum);
    }
    out.swap(next);return true;
}
struct SwiGluExpert { ExpertMatrix gate,up,down; };
inline bool ExecuteExpert(const SwiGluExpert& e,const std::vector<float>& x,std::vector<float>& out){
    std::vector<float> g,u;
    if(e.gate.rows!=e.up.rows||e.down.cols!=e.gate.rows||e.down.rows!=x.size()||
       !ExpertMatVec(e.gate,x,g)||!ExpertMatVec(e.up,x,u))return false;
    for(size_t i=0;i<g.size();++i){
        const double a=g[i];const double s=a>=0?1/(1+std::exp(-a)):std::exp(a)/(1+std::exp(a));
        const double v=a*s*u[i];
        if(!std::isfinite(v)||std::abs(v)>std::numeric_limits<float>::max())return false;
        g[i]=float(v);
    }
    return ExpertMatVec(e.down,g,out);
}
// Resolver supplies immutable matrix leases for each retained slot.
template<class Resolver>
bool ExecuteRoutedExperts(const std::vector<RouteChoice>& routes,const std::vector<float>& x,Resolver&& resolve,std::vector<float>& out){
    if(routes.empty()||x.empty())return false;
    std::vector<double> sum(x.size(),0);
    for(const auto& route:routes){
        if(!std::isfinite(route.weight)||route.weight<0)return false;
        SwiGluExpert e;std::vector<float> y;
        if(!resolve(route.retained,e)||!ExecuteExpert(e,x,y))return false;
        for(size_t i=0;i<sum.size();++i)sum[i]+=route.weight*y[i];
    }
    std::vector<float> next(x.size());
    for(size_t i=0;i<sum.size();++i){
        if(!std::isfinite(sum[i])||std::abs(sum[i])>std::numeric_limits<float>::max())return false;
        next[i]=float(sum[i]);
    }
    out.swap(next);return true;
}
} }
