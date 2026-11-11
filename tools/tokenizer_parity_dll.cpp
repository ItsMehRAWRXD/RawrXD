// RAW-XD tokenizer parity harness: compares the production DLL tokenizer
// (RawrXDCore_Tokenize) against llama.cpp reference ids for the frozen corpus.
#include <windows.h>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

typedef void* RawrXDModelHandle;
typedef void* RawrXDContextHandle;
typedef void* (*RawrXDTokenizeFn)(RawrXDModelHandle, const char*, int32_t**, uint32_t*);

extern "C" {
__declspec(dllimport) bool RawrXDCore_Initialize(void);
__declspec(dllimport) void RawrXDCore_Shutdown(void);
__declspec(dllimport) void* RawrXDCore_LoadModel(const char*);
__declspec(dllimport) void RawrXDCore_UnloadModel(void*);
__declspec(dllimport) size_t RawrXDCore_Tokenize(const void*, const char*,
                                                 int*, size_t);
}

static std::vector<std::string> LoadCorpus(const char* path)
{
    std::vector<std::string> cases;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) cases.push_back(line);
    }
    return cases;
}

static std::vector<std::vector<int32_t>> LoadRef(const char* path)
{
    std::vector<std::vector<int32_t>> out;
    std::ifstream in(path, std::ios::binary);
    if (!in) return out;
    uint32_t n = 0;
    in.read((char*)&n, 4);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t m = 0;
        in.read((char*)&m, 4);
        std::vector<int32_t> toks(m);
        if (m) in.read((char*)toks.data(), (std::streamsize) m * 4);
        out.push_back(toks);
    }
    return out;
}

int main(int argc, char** argv)
{
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s model corpus refbin [out_json]\n", argv[0]);
        return 2;
    }
    const char* model_path = argv[1];
    const char* corpus_path = argv[2];
    const char* ref_path = argv[3];
    const char* out_json = argc > 4 ? argv[4] : "tokenizer_parity.json";

    auto cases = LoadCorpus(corpus_path);
    auto refs = LoadRef(ref_path);
    if (cases.size() != refs.size()) {
        std::fprintf(stderr, "corpus/ref size mismatch: %zu vs %zu\n",
                     cases.size(), refs.size());
        return 3;
    }

    if (!RawrXDCore_Initialize()) { std::fprintf(stderr, "init failed\n"); return 4; }
    void* model = RawrXDCore_LoadModel(model_path);
    if (!model) { std::fprintf(stderr, "model load failed\n"); return 5; }

    uint32_t pass = 0, fail = 0;
    std::ofstream js(out_json);
    js << "{\n  \"cases\": [\n";
    for (size_t i = 0; i < cases.size(); ++i) {
        std::vector<int32_t> got(cases[i].size() + 32, 0);
        size_t n = RawrXDCore_Tokenize(model, cases[i].c_str(), got.data(),
                                       got.size());
        got.resize(n);
        std::vector<int32_t> want_nb(refs[i].begin(), refs[i].end());
        if (!want_nb.empty() && want_nb[0] == 100000) {
            want_nb.erase(want_nb.begin()); // drop reference BOS
        }
        const bool ok = (got == want_nb);
        if (ok) ++pass; else ++fail;
        js << "    {\"case\": " << i << ", \"pass\": " << (ok ? "true" : "false")
           << ", \"dll\": [";
        for (size_t j = 0; j < got.size(); ++j)
            js << (j ? ", " : "") << got[j];
        js << "], \"ref\": [";
        for (size_t j = 0; j < want_nb.size(); ++j)
            js << (j ? ", " : "") << want_nb[j];
        js << "]}" << (i + 1 < cases.size() ? "," : "") << "\n";
        std::printf("case %2zu: %s\n", i, ok ? "MATCH" : "DIFF ");
    }
    js << "  ],\n  \"pass\": " << pass << ", \"fail\": " << fail
       << ", \"total\": " << cases.size() << "\n}\n";

    RawrXDCore_UnloadModel(model);
    RawrXDCore_Shutdown();
    std::printf("TOKENIZER_PARITY pass=%u fail=%u total=%zu\n",
                pass, fail, cases.size());
    return fail == 0 ? 0 : 1;
}
