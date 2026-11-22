#pragma once
#include <vector>
#include <cmath>
#include <cstddef>
#include <limits>
#include <algorithm>
namespace Deep2 { namespace ReapQuant {
// Row-major per-head K/V projections; rotary keys already rotated,
// shared across heads. Query layout is [nonrotary, rotary] per head.
// Latents are post-normalization. No implicit RoPE or scale adjustment.
inline bool MlaReference(size_t heads,size_t rank,size_t nope,size_t rope,size_t value,
 size_t tokens,size_t position,double scale,const std::vector<float>& q,
 const std::vector<float>& latent,const std::vector<float>& rotatedKeys,
 const std::vector<float>& wk,const std::vector<float>& wv,std::vector<float>& out){
    const auto max=std::numeric_limits<size_t>::max();
    if(!heads||!rank||!nope||!rope||!value||!tokens||position>=tokens||
       !std::isfinite(scale)||scale<=0||nope>max-rope)return false;
    auto product=[&](size_t a,size_t b,size_t& c){if(b&&a>max/b)return false;c=a*b;return true;};
    size_t qs,ls,rs,ks,vs,os,kr,vr;
    if(!product(heads,nope+rope,qs)||!product(tokens,rank,ls)||
       !product(tokens,rope,rs)||!product(heads,nope,kr)||!product(kr,rank,ks)||
       !product(heads,value,vr)||!product(vr,rank,vs)||!product(heads,value,os)||
       q.size()!=qs||latent.size()!=ls||rotatedKeys.size()!=rs||wk.size()!=ks||wv.size()!=vs)return false;
    std::vector<float> next(os);
    std::vector<double> scores(position+1),compressed(rank),weighted(rank);
    for(size_t h=0;h<heads;++h){
        std::fill(compressed.begin(),compressed.end(),0);
        for(size_t d=0;d<nope;++d)for(size_t r=0;r<rank;++r)
            compressed[r]+=double(q[h*(nope+rope)+d])*wk[(h*nope+d)*rank+r];
        double peak=-std::numeric_limits<double>::infinity();
        for(size_t t=0;t<=position;++t){
            double s=0;
            for(size_t r=0;r<rank;++r)s+=compressed[r]*latent[t*rank+r];
            for(size_t d=0;d<rope;++d)s+=double(q[h*(nope+rope)+nope+d])*rotatedKeys[t*rope+d];
            scores[t]=s*scale;if(!std::isfinite(scores[t]))return false;
            peak=(std::max)(peak,scores[t]);
        }
        double mass=0;
        for(auto& s:scores){s=std::exp(s-peak);mass+=s;}
        if(!std::isfinite(mass)||mass<=0)return false;
        std::fill(weighted.begin(),weighted.end(),0);
        for(size_t t=0;t<=position;++t)for(size_t r=0;r<rank;++r)
            weighted[r]+=scores[t]/mass*latent[t*rank+r];
        for(size_t d=0;d<value;++d){
            double y=0;for(size_t r=0;r<rank;++r)y+=wv[(h*value+d)*rank+r]*weighted[r];
            if(!std::isfinite(y)||std::abs(y)>std::numeric_limits<float>::max())return false;
            next[h*value+d]=float(y);
        }
    }
    out.swap(next);return true;
}
} }
