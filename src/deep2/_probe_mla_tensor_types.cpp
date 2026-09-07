// _probe_mla_tensor_types.cpp — dump blk.0 MLA weight types/shapes
#include "Deep2Engine.h"
#include <cstdio>
#include <cstdlib>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace Deep2;
int main() {
  _putenv_s("RAWRXD_GPU_POLICY","SOLO");
  const char* dir="F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M";
  Deep2Engine e; EngineConfig c{};
  c.hiddenDim=7168;c.numLayers=61;c.numHeads=64;c.numKVHeads=1;c.vocabSize=163840;
  c.useMLA=true;c.maxSeqLen=128;c.useKVCache=true;c.useThreadPool=true;c.numThreads=4;
  if(!e.initialize(c)||!e.openK2ShardDirectory(dir)){puts("open fail");return 2;}
  auto* idx=e.k2TensorIndex();
  const char* names[]={
    "blk.0.attn_q_a.weight","blk.0.attn_q_b.weight","blk.0.attn_kv_a_mqa.weight",
    "blk.0.attn_k_b.weight","blk.0.attn_v_b.weight","blk.0.attn_output.weight"};
  for(auto* n: names){
    auto opt=idx->Find(n);
    if(!opt){printf("%s MISSING\n",n);continue;}
    auto& r=*opt;
    printf("%s type=%u nd=%u bytes=%llu shape=",n,r.ggmlType,r.nDims,
           (unsigned long long)r.byteSize);
    for(uint32_t i=0;i<r.nDims&&i<r.shape.size();++i) printf("%llu%s",
      (unsigned long long)r.shape[i], i+1<r.nDims?",":"");
    printf("\n");
  }
  return 0;
}
