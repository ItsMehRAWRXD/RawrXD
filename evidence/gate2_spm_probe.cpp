#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <array>
#include <algorithm>
#include "deep2/GGUFTokenizerLoad.hpp"
#include "tokenizer/sentencepiece_encode.hpp"

int main() {
  auto bundle = Deep2::LoadTokenizerFromGGUF(
      "F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf");
  if (!bundle.ok) { std::fprintf(stderr, "load fail %s\n", bundle.error); return 2; }
  std::unordered_map<std::string,int> vocab;
  std::array<int,256> byteFb; byteFb.fill(-1);
  for (size_t i=0;i<bundle.tokens.size();++i) {
    vocab[bundle.tokens[i]] = (int)i;
    const auto& p = bundle.tokens[i];
    if (p.size()==6 && p[0]=='<' && p[1]=='0' && p[2]=='x' && p[5]=='>') {
      int b=0; bool ok=true;
      for (size_t k=3;k<5;k++){ char c=p[k]; b*=16;
        if(c>='0'&&c<='9')b+=c-'0'; else if(c>='A'&&c<='F')b+=c-'A'+10; else if(c>='a'&&c<='f')b+=c-'a'+10; else {ok=false;break;} }
      if (ok && b>=0 && b<256 && byteFb[(size_t)b]<0) byteFb[(size_t)b]=(int)i;
    }
  }
  std::ifstream in("F:/rawrxd-native-agent-001/evidence/oracle_continuous_prompt.txt", std::ios::binary);
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  std::vector<int> ids;
  const float* scores = bundle.scores.empty()? nullptr : bundle.scores.data();
  RawrXD::Spm::encode(text, vocab, byteFb, scores, bundle.special.unkId, ids);
  std::printf("SPM_PROBE count=%zu\n", ids.size());
  std::printf("IDS=");
  for (size_t i=0;i<ids.size();++i) std::printf("%s%d", i?",":"", ids[i]);
  std::printf("\n");
  auto norm = RawrXD::Spm::normalizeMetaspace(text);
  std::printf("NORM_LEN=%zu HEAD=", norm.size());
  for (size_t i=0;i<(std::min)(norm.size(),(size_t)12);++i) std::printf("%02X", (unsigned char)norm[i]);
  std::printf("\n");
  static const char usp[] = "\xE2\x96\x81";
  std::string uu = std::string(usp,3)+std::string(usp,3);
  auto it = vocab.find(uu);
  std::printf("VOCAB_UU=%d\n", it==vocab.end()?-1:it->second);
  auto it2 = vocab.find(std::string(usp,3)+"#");
  std::printf("VOCAB_UHASH=%d\n", it2==vocab.end()?-1:it2->second);
  return 0;
}
