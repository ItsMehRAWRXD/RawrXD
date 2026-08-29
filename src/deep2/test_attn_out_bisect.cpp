#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
using Deep2::GGUFLoader;
using Deep2::QuantKernelRegistry;
static bool loadF32(const char* p,size_t n,std::vector<float>&o){FILE*f=fopen(p,"rb");if(!f)return false;o.resize(n);bool ok=fread(o.data(),4,n,f)==n;fclose(f);return ok;}
static double maxAbs(const float*a,const float*b,size_t n,int*fb){double m=0;*fb=-1;for(size_t i=0;i<n;++i){double d=fabs((double)a[i]-(double)b[i]);if(d>m){m=d;if(*fb<0&&d>1e-6)*fb=(int)i;}}return m;}
int main(){
  const char* v3=R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ORACLE_V3)";
  std::vector<float> deep2V,llamaV,deep2Out,llamaOut,attnNorm;
  loadF32((std::string(v3)+"\\deep2_V_0_pos0_layer0_full_n256_seq005.bin").c_str(),256,deep2V);
  loadF32((std::string(v3)+"\\llama_V_0_pos0_layer0_full_n256_seq045.bin").c_str(),256,llamaV);
  loadF32((std::string(v3)+"\\deep2_ATTN_OUT_0_pos0_layer0_full_n2048_seq008.bin").c_str(),2048,deep2Out);
  loadF32((std::string(v3)+"\\llama_ATTN_OUT_0_pos0_layer0_full_n2048_seq102.bin").c_str(),2048,llamaOut);
  // GQA expand: 32 heads, 4 kv heads, headDim=64 ? each KV head shared by 8 Q heads
  std::vector<float> preO(2048);
  for(int h=0;h<32;++h){
    int kv=h/8;
    memcpy(preO.data()+h*64, deep2V.data()+kv*64, 64*sizeof(float));
  }
  int fb=0;
  printf("deep2Out vs expand(V) max_abs=%.6e (expect FAIL if ATTN_OUT is post-O)\n", maxAbs(deep2Out.data(),preO.data(),2048,&fb));
  printf("llamaOut vs expand(V) max_abs=%.6e\n", maxAbs(llamaOut.data(),preO.data(),2048,&fb));
  printf("deep2Out vs llamaOut max_abs=%.6e\n", maxAbs(deep2Out.data(),llamaOut.data(),2048,&fb));

  auto lr=GGUFLoader::Load(R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)",{true,true,false});
  const auto* wo=lr.GetTensor("blk.0.attn_output.weight");
  printf("wo type=%d rows=%llu cols=%llu\n",(int)wo->type,(unsigned long long)wo->dimensions[1],(unsigned long long)wo->dimensions[0]);
  auto& reg=QuantKernelRegistry::Instance(); reg.Initialize();
  auto ker=reg.GetGEMV((int)wo->type);
  size_t rows=(size_t)wo->dimensions[1], cols=(size_t)wo->dimensions[0];
  std::vector<float> oDeep(rows,0.f), oLlamaIn(rows,0.f);
  // O(expand(deep2V)) and O(expand(llamaV)) ? should match if O kernel OK and attend=1
  ker((const uint8_t*)wo->data, preO.data(), oDeep.data(), rows, cols);
  std::vector<float> preL(2048);
  for(int h=0;h<32;++h){ int kv=h/8; memcpy(preL.data()+h*64, llamaV.data()+kv*64, 64*sizeof(float)); }
  std::vector<float> oFromL(rows,0.f);
  ker((const uint8_t*)wo->data, preL.data(), oFromL.data(), rows, cols);
  printf("O(expand(deep2V)) vs deep2 ATTN_OUT max_abs=%.6e first_bad=%d\n", maxAbs(oDeep.data(),deep2Out.data(),2048,&fb), fb);
  printf("O(expand(llamaV)) vs llama ATTN_OUT max_abs=%.6e first_bad=%d\n", maxAbs(oFromL.data(),llamaOut.data(),2048,&fb), fb);
  printf("O(expand(deep2V)) vs llama ATTN_OUT max_abs=%.6e first_bad=%d\n", maxAbs(oDeep.data(),llamaOut.data(),2048,&fb), fb);
  printf("O(expand(deep2V)) vs O(expand(llamaV)) max_abs=%.6e\n", maxAbs(oDeep.data(),oFromL.data(),2048,&fb));
  return 0;
}
