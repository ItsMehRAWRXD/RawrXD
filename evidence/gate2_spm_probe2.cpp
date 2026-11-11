#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include "deep2/GGUFTokenizerLoad.hpp"
#include "deep2/Tokenizer.hpp"
#include "tokenizer/sentencepiece_encode.hpp"

static void printIds(const char* tag, const std::vector<int>& ids) {
  std::printf("%s count=%zu\n", tag, ids.size());
  std::printf("%s_IDS=", tag);
  for (size_t i=0;i<ids.size();++i) std::printf("%s%d", i?",":"", ids[i]);
  std::printf("\n");
}

int main() {
  auto bundle = Deep2::LoadTokenizerFromGGUF(
      "F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf");
  if (!bundle.ok) { std::fprintf(stderr, "fail %s\n", bundle.error); return 2; }
  std::printf("tok29905=");
  if (bundle.tokens.size()>29905) {
    const auto& p=bundle.tokens[29905];
    for (unsigned char c: p) std::printf("%02X", c);
    std::printf(" str=%s\n", p.c_str());
  }
  std::printf("tok29876=");
  if (bundle.tokens.size()>29876) {
    const auto& p=bundle.tokens[29876];
    for (unsigned char c: p) std::printf("%02X", c);
    std::printf("\n");
  }
  std::ifstream in("F:/rawrxd-native-agent-001/evidence/oracle_continuous_prompt.txt", std::ios::binary);
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

  Deep2::BPETokenizer bpe;
  if (!Deep2::ApplyTokenizerBundle(bpe, bundle)) { std::fprintf(stderr,"apply fail\n"); return 3; }
  auto enc = bpe.Encode(text);
  printIds("BPE", enc);

  std::unordered_map<std::string,int> vocab;
  std::array<int,256> byteFb; byteFb.fill(-1);
  for (size_t i=0;i<bundle.tokens.size();++i) vocab[bundle.tokens[i]]=(int)i;
  std::vector<int> spm;
  RawrXD::Spm::encode(text, vocab, byteFb, bundle.scores.data(), bundle.special.unkId, spm);
  printIds("SPM", spm);

  // How many specials would Encode collect?
  int chatml=0;
  for (const auto& kv : /* can't access */ std::vector<int>{}) (void)kv;
  // Count <|...|> in vocab
  for (size_t i=0;i<bundle.tokens.size();++i) {
    const auto& p=bundle.tokens[i];
    if (p.size()>=5 && p.front()=='<' && p[1]=='|' && p.back()=='>' && p[p.size()-2]=='|') chatml++;
  }
  std::printf("CHATML_SPECIAL_CANDIDATES=%d\n", chatml);
  std::printf("BOS_STR=%s EOS_STR=%s\n", bundle.tokens[1].c_str(), bundle.tokens[2].c_str());
  return 0;
}
