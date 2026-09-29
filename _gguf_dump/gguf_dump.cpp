// gguf_dump.cpp — minimal GGUF v3 tensor/KV directory dumper (no deps).
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <cmath>
#include <fstream>
#include <iostream>

struct R {
    std::ifstream f;
    explicit R(const char* p) : f(p, std::ios::binary) {}
    template <class T> T rd() { T v{}; f.read(reinterpret_cast<char*>(&v), sizeof(T)); return v; }
    std::string str() {
        uint64_t n = rd<uint64_t>();
        std::string s; s.resize((size_t)n);
        f.read(s.data(), (std::streamsize)n);
        return s;
    }
    bool ok() const { return f.good(); }
};

static std::string gguf_type_name(uint32_t t) {
    switch (t) {
        case 0: return "F32"; case 1: return "F16";
        case 2: return "Q4_0"; case 3: return "Q4_1";
        case 6: return "Q5_0"; case 7: return "Q5_1";
        case 8: return "Q8_0"; case 9: return "Q8_1";
        case 10: return "Q2_K"; case 11: return "Q3_K"; case 12: return "Q4_K"; case 13: return "Q5_K";
        case 14: return "Q6_K"; case 15: return "Q8_K";
        case 16: return "IQ2_XXS"; case 17: return "IQ2_XS";
        case 30: return "BF16"; case 34: return "TQ1_0"; case 35: return "TQ2_0";
        default: { char b[32]; snprintf(b, sizeof b, "TYPE_%u", t); return b; }
    }
}

static void skip_value(std::ifstream& f, uint32_t t) {
    switch (t) {
        case 0: case 1: case 7: f.seekg(1, std::ios::cur); break;
        case 2: case 3: case 9: case 11: case 13: f.seekg(2, std::ios::cur); break;
        case 4: case 5: case 6: case 12: case 14: case 10: f.seekg(4, std::ios::cur); break;
        case 30: f.seekg(2, std::ios::cur); break;
        case 8: case 34: case 35: f.seekg(8, std::ios::cur); break;
        case 15: case 16: case 17: case 18: case 19: case 20: case 21:
        case 22: case 23: case 24: case 25: case 26: case 27: case 28:
        case 29: case 31: case 32: case 33: f.seekg(4, std::ios::cur); break;
        default: f.seekg(4, std::ios::cur); break;
    }
}

int main(int argc, char** argv) {
    if (argc < 2) { std::printf("usage: gguf_dump <file.gguf>\n"); return 1; }
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    R r(argv[1]);
    if (!r.ok()) { std::printf("ERR cannot open %s\n", argv[1]); return 1; }

    std::printf("STAGE=header\n");
    uint32_t magic = r.rd<uint32_t>();
    uint32_t version = r.rd<uint32_t>();
    uint64_t nTensors = r.rd<uint64_t>();
    uint64_t nKV = r.rd<uint64_t>();
    std::printf("GGUF_MAGIC=0x%08X VERSION=%u N_TENSORS=%llu N_KV=%llu\n",
                magic, version, (unsigned long long)nTensors, (unsigned long long)nKV);

    // --- KV metadata ---
    std::printf("STAGE=kv_parse n=%llu\n", (unsigned long long)nKV);
    uint32_t kvStringT = (version == 2) ? 8u : 8u;
    uint32_t kvArrayT  = (version == 2) ? 9u : 9u;
    for (uint64_t i = 0; i < nKV; i++) {
        std::string key = r.str();
        uint32_t type = r.rd<uint32_t>();
        if (type == 8) {           // string
            std::string val = r.str();
            if (key.find("head") != std::string::npos || key.find("norm") != std::string::npos ||
                key.find("rope") != std::string::npos || key.find("expert") != std::string::npos ||
                key.find("arch") != std::string::npos || key.find("vocab") != std::string::npos)
                std::printf("KV  %-46s = %s\n", key.c_str(),
                            val.size() > 110 ? (val.substr(0, 110) + "...").c_str() : val.c_str());
        } else if (type == 9) {    // array
            uint32_t elemType = r.rd<uint32_t>();
            uint64_t n = r.rd<uint64_t>();
            if (key == "tokenizer.ggml.tokens" || key == "tokenizer.ggml.merges" ||
                key == "tokenizer.ggml.token_type" || key == "general.tags" ||
                key == "general.languages" || key == "general.base_model.0.name") {
                std::printf("KV  %-46s = [array type=%s n=%llu]\n", key.c_str(),
                            gguf_type_name(elemType).c_str(), (unsigned long long)n);
            }
            for (uint64_t j = 0; j < n; j++) {
                if (elemType == 8) r.str();
                else skip_value(r.f, elemType);
            }
        } else {
            std::streampos here = r.f.tellg();
            if (key.find("head") != std::string::npos || key.find("norm") != std::string::npos ||
                key.find("rope") != std::string::npos || key.find("context") != std::string::npos ||
                key.find("length") != std::string::npos || key.find("head_count") != std::string::npos ||
                key.find("epsilon") != std::string::npos || key.find("type") != std::string::npos) {
                r.f.seekg(here);
                double dv = 0; int64_t iv = 0; uint64_t uv = 0;
                if (type == 4) { iv = r.rd<int32_t>(); std::printf("KV  %-46s = %lld\n", key.c_str(), (long long)iv); }
                else if (type == 5) { iv = r.rd<int32_t>(); std::printf("KV  %-46s = %lld\n", key.c_str(), (long long)iv); }
                else if (type == 6) { dv = r.rd<float>();  std::printf("KV  %-46s = %g\n", key.c_str(), dv); }
                else if (type == 7) { uv = r.rd<uint8_t>(); std::printf("KV  %-46s = %llu\n", key.c_str(), (unsigned long long)uv); }
                else if (type == 10) { uv = r.rd<uint64_t>(); std::printf("KV  %-46s = %llu\n", key.c_str(), (unsigned long long)uv); }
                else if (type == 1) { uv = r.rd<uint8_t>(); std::printf("KV  %-46s = %llu\n", key.c_str(), (unsigned long long)uv); }
                else if (type == 0) { uv = r.rd<uint8_t>(); std::printf("KV  %-46s = %llu\n", key.c_str(), (unsigned long long)uv); }
                else { r.f.seekg(here); skip_value(r.f, type); }
            } else {
                skip_value(r.f, type);
            }
        }
        if (!r.ok()) { std::printf("ERR KV parse failed at %llu\n", (unsigned long long)i); return 2; }
    }

    // --- Tensor directory ---
    std::printf("STAGE=tensor_parse n=%llu\n", (unsigned long long)nTensors);
    struct T { std::string n; std::vector<uint64_t> dims; uint32_t type; uint64_t off; };
    std::vector<T> tensors;
    tensors.reserve((size_t)nTensors);
    for (uint64_t i = 0; i < nTensors; i++) {
        T t;
        t.n = r.str();
        uint32_t ndims = r.rd<uint32_t>();
        t.dims.resize(ndims);
        for (uint32_t d = 0; d < ndims; d++) t.dims[d] = r.rd<uint64_t>();
        t.type = r.rd<uint32_t>();
        t.off = r.rd<uint64_t>();
        tensors.push_back(t);
        if (!r.ok()) { std::printf("ERR tensor parse failed at %llu name=%s\n",
                                    (unsigned long long)i, t.n.c_str()); return 3; }
    }

    auto dimstr = [](const T& t) {
        char b[128]; b[0] = 0;
        for (size_t i = 0; i < t.dims.size() && i < 4; i++) {
            char one[32]; snprintf(one, sizeof one, "%s%llu", i ? "x" : "", (unsigned long long)t.dims[i]);
            strncat(b, one, sizeof(b) - strlen(b) - 1);
        }
        return std::string(b);
    };
    if (!r.ok()) { std::printf("ERR tensor parse failed\n"); return 3; }

    std::printf("\n=== TENSORS OF INTEREST (total=%llu) ===\n", (unsigned long long)nTensors);
    for (auto& t : tensors) {
        const std::string& n = t.n;
        bool interesting =
            n.find("output") != std::string::npos ||
            n.find("lm_head") != std::string::npos ||
            n.find("token_embd") != std::string::npos ||
            n.find("attn_q") != std::string::npos ||
            n.find("attn_k") != std::string::npos ||
            n.find("attn_v") != std::string::npos ||
            n.find("attn_output") != std::string::npos ||
            n.find("ffn_gate") != std::string::npos ||
            n.find("ffn_up") != std::string::npos ||
            n.find("ffn_down") != std::string::npos ||
            n.find("norm") != std::string::npos;
        if (interesting) {
            std::printf("%-44s dims=%-24s type=%-6s off=%llu\n",
                        n.c_str(), dimstr(t).c_str(),
                        gguf_type_name(t.type).c_str(), (unsigned long long)t.off);
        }
    }

    // --- Bias census (only for blk.0) ---
    std::printf("\n=== BLK.0 CENSUS ===\n");
    for (auto& t : tensors) {
        if (t.n.rfind("blk.0.", 0) == 0)
            std::printf("%-44s dims=%-24s type=%s\n", t.n.c_str(), dimstr(t).c_str(),
                        gguf_type_name(t.type).c_str());
    }

    // --- Geometry assertions ---
    std::printf("\n=== GEOMETRY ===\n");
    auto find = [&](const char* nm) -> const T* {
        for (auto& t : tensors) if (t.n == nm) return &t; return nullptr;
    };
    auto findSuffix = [&](const char* suf) -> const T* {
        for (auto& t : tensors) if (t.n.size() > 2 && t.n.rfind("blk.0.", 0) == 0 &&
                                   t.n.size() >= strlen(suf) &&
                                   t.n.compare(t.n.size() - strlen(suf), strlen(suf), suf) == 0) return &t;
        return nullptr;
    };
    struct Probe { const char* label; const char* exact; const char* suf; };
    const Probe probes[] = {
        {"TOKEN_EMBD",   "token_embd.weight",   nullptr},
        {"LM_HEAD_out",  "output.weight",       nullptr},
        {"LM_HEAD_alt",  "lm_head.weight",      nullptr},
        {"ATTN_Q",       "blk.0.attn_q.weight", nullptr},
        {"ATTN_K",       "blk.0.attn_k.weight", nullptr},
        {"ATTN_V",       "blk.0.attn_v.weight", nullptr},
        {"ATTN_OUTPUT",  "blk.0.attn_output.weight", nullptr},
        {"FFN_GATE",     "blk.0.ffn_gate.weight", nullptr},
        {"FFN_UP",       "blk.0.ffn_up.weight",   nullptr},
        {"FFN_DOWN",     "blk.0.ffn_down.weight", nullptr},
        {"Q_BIAS",       "blk.0.attn_q.bias",  ".attn_q.bias"},
        {"K_BIAS",       "blk.0.attn_k.bias",  ".attn_k.bias"},
        {"V_BIAS",       "blk.0.attn_v.bias",  ".attn_v.bias"},
        {"FINAL_NORM",   "output_norm.weight", nullptr},
    };
    for (auto& p : probes) {
        const T* t = p.exact ? find(p.exact) : findSuffix(p.suf);
        if (t)
            std::printf("%-14s PRESENT=1 dims=%-24s type=%-6s off=%llu\n",
                        p.label, dimstr(*t), gguf_type_name(t->type).c_str(),
                        (unsigned long long)t->off);
        else
            std::printf("%-14s PRESENT=0\n", p.label);
    }
    std::printf("\nGGUF_DUMP_DONE\n");
    return 0;
}
