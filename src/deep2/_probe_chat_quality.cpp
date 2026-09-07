#include "GGUFLoader.hpp"
#include <cstdio>
using namespace Deep2;
int main(){
  auto r=GGUFLoader::LoadMetadata("G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf");
  printf("arch=%s vocabMeta=%u hidden=%u\n", r.metadata.architecture.c_str(), r.metadata.vocabSize, r.metadata.hiddenSize);
  for (auto& t: r.tensors) {
    if (t.name.find("output")!=std::string::npos || t.name.find("token_embd")!=std::string::npos || t.name.find("embd")!=std::string::npos) {
      printf("%s type=%d dims=", t.name.c_str(), (int)t.type);
      for (auto d: t.dimensions) printf("%llu ", (unsigned long long)d);
      printf("size=%llu\n", (unsigned long long)t.size);
    }
  }
  // chat template snippet
  printf("chatTemplate_len=%zu head=%.80s\n", r.metadata.chatTemplate.size(), r.metadata.chatTemplate.c_str());
}
