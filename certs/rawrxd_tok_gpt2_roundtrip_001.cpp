// certs/rawrxd_tok_gpt2_roundtrip_001.cpp — fast U08 tokenizer owner probe
#include "../src/deep2/GGUFTokenizerLoad.hpp"
#include <cstdio>
#include <string>

static bool NormEq(std::string a, std::string b) {
    auto trim = [](std::string& s) {
        while (!s.empty() && (s.back() == ' ' || s.back() == '\n')) s.pop_back();
        size_t i = 0;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\n')) ++i;
        s = s.substr(i);
    };
    trim(a);
    trim(b);
    return a == b;
}

int main() {
    using namespace Deep2;
    const char* path = "G:\\~dev\\rawrxd\\llama3.2-3b-Q3_K_S.gguf";
    auto bundle = LoadTokenizerFromGGUF(path);
    if (!bundle.ok) {
        printf("LOAD=0 ERR=%s\n", bundle.error);
        puts("RAWRXD_TOK_GPT2_ROUNDTRIP_001=FAIL");
        return 1;
    }
    BPETokenizer tok;
    if (!ApplyTokenizerBundle(tok, bundle)) {
        puts("APPLY=0");
        puts("RAWRXD_TOK_GPT2_ROUNDTRIP_001=FAIL");
        return 1;
    }
    printf("TOKENIZER_MODEL=%s GPT2=%d MERGES=%zu\n", tok.TokenizerModel().c_str(),
           tok.IsGpt2() ? 1 : 0, bundle.merges.size());
    const char* probe = "The quick brown fox";
    auto ids = tok.Encode(probe);
    std::string back = tok.Decode(ids);
    printf("IDS=");
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i) putchar(',');
        printf("%d", ids[i]);
    }
    putchar('\n');
    printf("BACK=[%s]\n", back.c_str());
    const int ok = NormEq(back, probe) ? 1 : 0;
    printf("TOKENIZER_ROUNDTRIP=%d\n", ok);
    puts(ok ? "RAWRXD_TOK_GPT2_ROUNDTRIP_001=PASS"
            : "RAWRXD_TOK_GPT2_ROUNDTRIP_001=FAIL");
    return ok ? 0 : 1;
}
