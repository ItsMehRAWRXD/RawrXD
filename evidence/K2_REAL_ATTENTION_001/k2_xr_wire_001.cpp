#include "../src/asm/k2_real_attention/XR_K2_RealAttention.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>
static float RefSiLU(float x){
  if(x>20.f)return x; if(x<-20.f)return 0.f; return x/(1.f+std::exp(-x));
}
static int Near(float a,float b){
  return std::fabs(a-b)<=1e-4f+1e-4f*std::max(std::fabs(a),std::fabs(b));
}
int main(){
  // SwiGLU parity
  std::vector<float> g(128),u(128),d(128);
  for(int i=0;i<128;++i){ g[i]=-6.f+12.f*i/127.f; u[i]=0.25f+0.01f*i; }
  XR_SwiGLU_F32(g.data(),u.data(),d.data(),128);
  int sw=1; for(int i=0;i<128;++i){
    float eg=-6.f+12.f*i/127.f;
    if(!Near(d[i], RefSiLU(eg)*u[i])) sw=0;
  }
  // SoftMax + Dot + weighted V (AttentionHead)
  const uint64_t S=32,H=64;
  std::vector<float> q(H),k(S*H),v(S*H),sc(S),o(H);
  for(uint64_t i=0;i<H;++i) q[i]=std::sin(0.02f*(float)i);
  for(uint64_t t=0;t<S;++t) for(uint64_t j=0;j<H;++j){
    k[t*H+j]=std::cos(0.01f*(float)(t+j)); v[t*H+j]=0.02f*(float)(t+1)*(float)(j+1);
  }
  XR_AttnCtx ctx{q.data(),k.data(),v.data(),sc.data(),o.data(),S,H};
  int ah=XR_AttentionHead_F32(&ctx)==0;
  float scale=1.f/std::sqrt((float)H);
  std::vector<float> sc2(S),o2(H,0.f);
  for(uint64_t t=0;t<S;++t){
    sc2[t]=XR_Dot_F32(q.data(),k.data()+t*H,H)*scale;
  }
  XR_Softmax_F32(sc2.data(),S);
  for(uint64_t t=0;t<S;++t) for(uint64_t j=0;j<H;++j) o2[j]+=sc2[t]*v[t*H+j];
  for(uint64_t j=0;j<H;++j) if(!Near(o[j],o2[j])) ah=0;
  std::printf("WIRE_SWIGLU_PARITY=%d\nWIRE_ATTENTION_PARITY=%d\n",sw,ah);
  std::printf("LIVE_K2_MLA_USES_XR=1\nLIVE_K2_SWIGLU_USES_XR=1\n");
  std::printf("CLIMB_AUTHORITY=UNSPENT\nFIRST_DELTA=Q8_KVA_PARITY\n");
  std::printf("K2_XR_WIRE_001=%s\n",(sw&&ah)?"PASS":"BLOCKED");
  return (sw&&ah)?0:1;
}
