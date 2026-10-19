#include "src/deep2/GGUFLoader.hpp"
#include <cstdio>
int main(){
  auto r=Deep2::GGUFLoader::LoadMetadata("G:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf");
  for(const auto& kv: r.rawKv){
    if(kv.first.find("tokenizer")!=std::string::npos || kv.first.find("bos")!=std::string::npos
       || kv.first.find("eos")!=std::string::npos || kv.first.find("chat_template")!=std::string::npos
       || kv.first.find("vocab")!=std::string::npos)
      printf("%s=%s\n", kv.first.c_str(), kv.second.size()>80 ? (kv.second.substr(0,80)+"...").c_str() : kv.second.c_str());
  }
  printf("meta vocab=%u bos=%s eos=%s tmpl_len=%zu\n", r.metadata.vocabSize, r.metadata.bosToken.c_str(),
         r.metadata.eosToken.c_str(), r.metadata.chatTemplate.size());
  return 0;
}
