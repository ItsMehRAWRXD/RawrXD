#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include "deep2/GGUFTokenizerLoad.hpp"
#include "deep2/Tokenizer.hpp"
int main() {
  auto bundle = Deep2::LoadTokenizerFromGGUF("F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf");
  if (!bundle.ok) return 2;
  Deep2::BPETokenizer bpe;
  if (!Deep2::ApplyTokenizerBundle(bpe, bundle)) return 3;
  std::ifstream in("F:/rawrxd-native-agent-001/evidence/oracle_continuous_prompt.txt", std::ios::binary);
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto enc = bpe.Encode(text);
  auto pol = [&](){
    std::vector<int> ids;
    if (bundle.addBos) ids.push_back(bundle.special.bosId);
    ids.insert(ids.end(), enc.begin(), enc.end());
    return ids;
  }();
  std::printf("NATIVE_BPE count=%zu first=%d second=%d\n", enc.size(), enc.empty()?-1:enc[0], enc.size()>1?enc[1]:-1);
  std::printf("WITH_BOS count=%zu first=%d\n", pol.size(), pol.empty()?-1:pol[0]);
  std::printf("addBos=%d bosId=%d\n", (int)bundle.addBos, bundle.special.bosId);
  return 0;
}
