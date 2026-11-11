// RAW-XD tokenizer reference: llama.cpp tokenization for parity comparison.
// Usage: rawrxd_tok_ref <corpus_file> <out_bin>
// Each corpus line is one case; the token id lists are written as binary
// int32 arrays (count + ids) so the production DLL tokenizer can be diffed.
#include <llama.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 3) { std::fprintf(stderr, "usage: %s corpus out\n", argv[0]); return 1; }
    std::ifstream in(argv[1]);
    if (!in) { std::fprintf(stderr, "corpus open failed\n"); return 1; }
    std::vector<std::string> cases;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        cases.push_back(line);
    }
    llama_backend_init();
    llama_model_params mp = llama_model_default_params();
    mp.n_gpu_layers = 0;
    mp.vocab_only = true;
    llama_model* model = llama_model_load_from_file("F:\\rawrxd\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf", mp);
    if (!model) { std::fprintf(stderr, "model load failed\n"); return 1; }
    const llama_vocab* vocab = llama_model_get_vocab(model);

    std::ofstream out(argv[2], std::ios::binary);
    uint32_t n = (uint32_t) cases.size();
    out.write((const char*)&n, 4);
    for (size_t i = 0; i < cases.size(); ++i) {
        std::vector<llama_token> toks(cases[i].size() + 16);
        int32_t n_tok = llama_tokenize(vocab, cases[i].c_str(), (int)cases[i].size(),
                                       toks.data(), (int)toks.size(), true, true);
        if (n_tok < 0) { n_tok = 0; }
        toks.resize(n_tok);
        uint32_t m = (uint32_t) n_tok;
        out.write((const char*)&m, 4);
        out.write((const char*)toks.data(), (std::streamsize)(n_tok * sizeof(llama_token)));
        std::printf("case %zu: %d tokens:", i, n_tok);
        for (int j = 0; j < n_tok && j < 24; ++j) std::printf(" %d", toks[j]);
        std::printf("\n");
    }
    llama_model_free(model);
    llama_backend_free();
    return 0;
}
