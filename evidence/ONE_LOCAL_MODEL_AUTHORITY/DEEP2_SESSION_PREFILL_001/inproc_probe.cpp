#include "src/deep2/Deep2Engine.h"
#include "src/deep2/RawrRunSession.hpp"
#include <cstdio>
int main() {
  Deep2::Deep2Engine e;
  Deep2::rawr_run::RunWitness w{};
  const char* p = "G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
  if (!Deep2::rawr_run::InitFromPath(e, p)) { printf("INIT_FAIL\n"); return 2; }
  printf("LOADED hidden=%zu layers=%zu\n", e.getModelWeights().hiddenDim, e.getModelWeights().numLayers);
  int n=0; std::string t;
  Deep2::GenerationOptions o{}; o.maxTokens=1; o.temperature=0; o.topK=1;
  e.generateStream("hi", o, [&](int32_t id, const std::string& piece){ ++n; t+=piece; printf("TOK id=%d piece=%s\n", (int)id, piece.c_str()); return true; });
  printf("N=%d bytes=%zu\n", n, t.size());
  return n>0?0:1;
}
