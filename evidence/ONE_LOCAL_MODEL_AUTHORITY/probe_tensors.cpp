#include "src/deep2/GGUFLoader.hpp"
#include <cstdio>
int main(){
  auto r=Deep2::GGUFLoader::LoadMetadata("G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf");
  if(!r.success){printf("FAIL %s\n",r.error);return 1;}
  printf("n=%zu vocab=%u\n",r.tensors.size(),r.metadata.vocabSize);
  for(size_t i=0;i<r.tensors.size();++i){
    const auto& t=r.tensors[i];
    printf("%s type=%u dims=",t.name.c_str(),(unsigned)t.type);
    for(size_t d=0;d<t.dimensions.size();++d) printf("%s%llu",d?",":"",(unsigned long long)t.dimensions[d]);
    printf(" off=%llu size=%zu\n",(unsigned long long)t.offset,t.size);
  }
  return 0;
}
