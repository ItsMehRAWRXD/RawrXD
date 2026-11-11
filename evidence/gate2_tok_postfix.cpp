#include <cstdio>
#include <fstream>
#include <string>
#include <vector>
#include "deep2/CanonicalTokenizer.hpp"
int main() {
  const char* model = "F:/rawrxd/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
  if (!Deep2::CanonicalTokenizer::Instance().LoadFromGGUF(model)) {
    std::fprintf(stderr, "load fail %s\n", Deep2::CanonicalTokenizer::Instance().LastError().c_str());
    return 2;
  }
  std::ifstream in("F:/rawrxd-native-agent-001/evidence/oracle_continuous_prompt.txt", std::ios::binary);
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  auto body = Deep2::CanonicalTokenizer::Instance().Encode(text);
  auto pol = Deep2::CanonicalTokenizer::Instance().EncodeWithPolicy(text);
  std::printf("BODY=%zu POLICY=%zu addBos=%d\n", body.size(), pol.size(),
              (int)Deep2::CanonicalTokenizer::Instance().AddBos());
  std::FILE* f = std::fopen("F:/rawrxd-native-agent-001/evidence/deep2_tokenize_dump.txt", "wb");
  std::fprintf(f, "DEEP2_POST_FIX prompt_tokens=%zu add_bos=%d source=CanonicalTokenizer::EncodeWithPolicy\n",
               pol.size(), (int)Deep2::CanonicalTokenizer::Instance().AddBos());
  for (size_t i=0;i<pol.size();++i) {
    std::string piece = Deep2::CanonicalTokenizer::Instance().Decode((int)pol[i]);
    for (char& c: piece) { if (c=='\n') { /* mark */ } }
    std::string shown;
    for (unsigned char c: piece) {
      if (c=='\n') shown += "\\n";
      else if (c=='\r') shown += "\\r";
      else if (c=='\t') shown += "\\t";
      else shown.push_back((char)c);
    }
    std::fprintf(f, "[%zu] %d -> '%s'\n", i, pol[i], shown.c_str());
  }
  std::fprintf(f, "COUNT=%zu\n", pol.size());
  std::fclose(f);
  std::printf("IDS=");
  for (size_t i=0;i<pol.size();++i) std::printf("%s%d", i?",":"", pol[i]);
  std::printf("\n");
  return 0;
}
