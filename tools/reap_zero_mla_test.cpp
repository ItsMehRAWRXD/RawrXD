#include "vulkan_compute.h"

#include <cmath>
#include <cstdio>
#include <vector>

int main() {
    constexpr uint32_t H=16, QD=192, VD=128, NOPE=128, ROPE=64, POS=1;
    Deep2::VulkanCompute vk(0);
    if (!vk.initialize() || !vk.EnsureForwardArena(4096, 4096, H, H, 128, 2, 1)) return 2;
    std::vector<float> q(H*QD), k((POS+1)*H*NOPE), v((POS+1)*H*VD), kp((POS+1)*ROPE), expected(H*VD), actual(H*VD);
    for (size_t i=0;i<q.size();++i) q[i]=std::sin(float(i)*0.013f)*0.25f;
    for (size_t i=0;i<k.size();++i) k[i]=std::cos(float(i)*0.017f)*0.2f;
    for (size_t i=0;i<v.size();++i) v[i]=std::sin(float(i)*0.019f)*0.3f;
    for (size_t i=0;i<kp.size();++i) kp[i]=std::cos(float(i)*0.023f)*0.1f;
    const float scale=1.0f/std::sqrt(float(QD));
    for(uint32_t h=0;h<H;++h){
        float qq[QD]; for(uint32_t d=0;d<QD;++d) qq[d]=q[h*QD+d];
        auto rot=[](float* x,uint32_t base,uint32_t dim,uint32_t p){uint32_t half=dim/2;for(uint32_t i=0;i<half;++i){float a=float(p)*std::pow(1.0e7f,-2.0f*float(i)/float(dim));float c=std::cos(a),s=std::sin(a),x0=x[base+i],x1=x[base+half+i];x[base+i]=x0*c-x1*s;x[base+half+i]=x0*s+x1*c;}};
        rot(qq,NOPE,ROPE,POS); float scores[POS+1],mx=-INFINITY;
        for(uint32_t t=0;t<=POS;++t){float kk[QD]{};for(uint32_t d=0;d<NOPE;++d)kk[d]=k[(t*H+h)*NOPE+d];for(uint32_t d=0;d<ROPE;++d)kk[NOPE+d]=kp[t*ROPE+d];rot(kk,NOPE,ROPE,t);float dot=0;for(uint32_t d=0;d<QD;++d)dot+=qq[d]*kk[d];scores[t]=dot*scale;mx=std::max(mx,scores[t]);}
        float den=std::exp(scores[0]-mx)+std::exp(scores[1]-mx);
        for(uint32_t d=0;d<VD;++d) expected[h*VD+d]=(std::exp(scores[0]-mx)*v[(h)*VD+d]+std::exp(scores[1]-mx)*v[(H+h)*VD+d])/den;
    }
    if(!vk.UploadVector(vk.ArenaQ(),q.data(),q.size())||!vk.UploadVector(vk.ArenaKCache(),k.data(),k.size())||!vk.UploadVector(vk.ArenaVCache(),v.data(),v.size())||!vk.UploadVector(vk.ArenaHidden(),kp.data(),kp.size())) return 3;
    const bool invalidRejected = !vk.DispatchAttnDecodeMLA(vk.ArenaQ(),vk.ArenaKCache(),vk.ArenaVCache(),vk.ArenaHidden(),vk.ArenaAttn(),193,VD,NOPE,ROPE,H,POS,1.0e7f,scale,1.0f,0);
    if (!invalidRejected) return 7;
    for(int i=0;i<2;++i){
        if(!vk.DispatchAttnDecodeMLA(vk.ArenaQ(),vk.ArenaKCache(),vk.ArenaVCache(),vk.ArenaHidden(),vk.ArenaAttn(),QD,VD,NOPE,ROPE,H,POS,1.0e7f,scale,1.0f,0)) return 4;
        if(!vk.DownloadVector(vk.ArenaAttn(),actual.data(),actual.size())) return 5;
    }
    float mx=0,rms=0; for(size_t i=0;i<actual.size();++i){float e=std::fabs(actual[i]-expected[i]);mx=std::max(mx,e);rms+=e*e;} rms=std::sqrt(rms/actual.size());
    std::printf("REAP_ZERO_MLA_MAX_ABS=%.9g RMS=%.9g REPEATED=1 INVALID_REJECTED=1 RESULT=%s\n",mx,rms,(mx<2e-4f)?"PASS":"FAIL");
    return mx<2e-4f?0:6;
}
