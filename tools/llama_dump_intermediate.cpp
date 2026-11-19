// ============================================================================
// llama_dump_intermediate.cpp -- per-layer REFERENCE oracle for Deep2
// ============================================================================
// Purpose
//   Export the SAME tensor boundaries Deep2 already exports, from llama.cpp,
//   so the FIRST divergent operator can be named instead of inferred from
//   final logits. Final-logit comparison cannot separate "wrong attention"
//   from "wrong FFN" from "wrong output projection"; per-layer capture can.
//
// Critical fixes over the previous revision (do not regress these):
//
//   1. ASK SEMANTICS. ggml's eval callback fires TWICE per node: once with
//      ask=true BEFORE the node is computed (the return value may skip it),
//      and once with ask=false AFTER. The previous revision ignored `ask` and
//      copied t->data unconditionally, so every "captured" tensor was read
//      before it existed - garbage that would silently poison any comparison.
//      We now capture ONLY when ask == false.
//
//   2. OPERATOR BOUNDARY AMBIGUITY. llama.cpp produces BOTH
//        kqv_out-<L>   the concatenated head outputs (attention BEFORE O_proj)
//        attn_out-<L>  the result after the O_proj matmul (attention AFTER)
//      Collapsing both into one name is exactly the "is attn_out before or
//      after output projection" trap. They are now exported as distinct
//      boundaries: attn_preproj and attn_proj.
//
//   3. DIMENSIONS ARE NOT HARDCODED. n_embd and n_vocab are queried from the
//      model. A hardcoded 3072/128256 silently truncates any other model and
//      turns a size mismatch into a bogus numerical error.
//
//   4. A MANIFEST IS EMITTED. Every dump records raw ggml name, element count
//      and shape, so an alignment step can prove shapes match element-for-
//      element before any tolerance is applied.
//
// Usage:
//   llama_dump_intermediate.exe <model.gguf> <tokens_file> <output_dir>
//                               [--max-layer N] [--no-hidden] [--no-logits]
//
// Output layout (one subdirectory per position):
//   <out>/pos<0>/<boundary>.bin          float32, ggml order (ne[0] fastest)
//   <out>/pos<0>/manifest.txt            name raw_name ne0 ne1 ne2 ne3 elems
//   <out>/pos<0>/logits.bin              full vocabulary logits (optional)
//   <out>/pos<0>/final_hidden.bin        final hidden state (optional)
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <filesystem>
#include <algorithm>

#include "llama.h"
#include "ggml.h"
#include "ggml-backend.h"

namespace fs = std::filesystem;

namespace {

struct Dump {
    std::string boundary;      // our stable name, e.g. "attn_proj"
    std::string raw_name;      // the ggml node name it came from
    int layer = -1;
    int64_t ne[4] = {0, 0, 0, 0};
    int64_t elems = 0;
    std::vector<float> data;
};

std::mutex              g_mu;
std::vector<Dump>       g_dumps;
int                     g_pos = 0;
std::string             g_out_dir;
int                     g_n_embd  = 0;
int                     g_n_vocab = 0;
int                     g_max_layer = -1;   // <0 = all

// Raw llama.cpp node names differ between graph shapes and releases. The match
// table is ordered most-specific-first, because "attn_out" is a prefix of
// nothing but "kqv_out" must not be swallowed by an "attn_out" rule.
struct Rule {
    const char* needle;
    const char* boundary;
};

const Rule kRules[] = {
    // ---- attention pre-projection (BEFORE O_proj) -------------------------
    { "kqv_out",        "attn_preproj"   },
    // ---- attention post-projection (AFTER O_proj) -------------------------
    { "attn_out",       "attn_proj"      },
    // ---- query/key/value, post-RoPE ---------------------------------------
    { "Qcur",           "q"              },
    { "Kcur",           "k"              },
    { "Vcur",           "v"              },
    { "Qcur_roped",     "q"              },
    { "Kcur_roped",     "k"              },
    // ---- norms ------------------------------------------------------------
    { "attn_norm",      "attn_norm"      },
    { "ffn_norm",       "ffn_norm"       },
    { "result_norm",    "out_norm"       },
    // ---- FFN --------------------------------------------------------------
    { "ffn_gate",       "ffn_gate"       },
    { "ffn_up",         "ffn_up"         },
    { "ffn_swiglu",     "ffn_swiglu"     },
    // llama.cpp names the down-projection RESULT "ffn_out-<L>" (the weight is
    // ffn_down); both spellings must map to the same Deep2 boundary.
    { "ffn_out",        "ffn_down"       },
    { "ffn_down",       "ffn_down"       },
    // ---- block residual / layer boundaries --------------------------------
    { "l_out",          "resid2"         },   // block output (residual after FFN)
    { "ffn_inp",        "attn_resid"     },   // residual AFTER attention (pre-FFN)
    { "inpL",           "resid_in"       },   // block input (residual entering)
    { "inp_tokens",     "token_embd"     },
    { "result_output",  "logits"         },
};

// Layer index is the suffix after the last '-'. Returns -1 when absent.
int ExtractLayer(const std::string& n) {
    const size_t dash = n.rfind('-');
    if (dash == std::string::npos || dash + 1 >= n.size()) return -1;
    const std::string tail = n.substr(dash + 1);
    if (tail.empty()) return -1;
    for (char c : tail) if (c < '0' || c > '9') return -1;
    try { return std::stoi(tail); } catch (...) { return -1; }
}

const char* MatchBoundary(const std::string& n) {
    // Longest matching needle wins; ties broken by table order.
    const char* best = nullptr;
    size_t best_len = 0;
    for (const auto& r : kRules) {
        const size_t len = std::strlen(r.needle);
        if (len < best_len) continue;
        if (n.find(r.needle) != std::string::npos) {
            best = r.boundary;
            best_len = len;
        }
    }
    return best;
}

bool GraphNodeCallback(ggml_tensor* t, bool ask, void* /*user_data*/) {
    // (1) ASK SEMANTICS. Only the post-compute callback has valid data.
    if (ask) return true;
    if (!t || !t->data || !t->name) return true;

    // Activations we want are F32; quantised weights are not boundaries.
    if (t->type != GGML_TYPE_F32) return true;

    const std::string raw(t->name);
    // (a) "(view)" nodes are aliases of a real node (Kcur/Qcur viewed into
    //     head layout for the mask path). They carry no layer suffix, so they
    //     all landed in an L=-1 bucket and buried the real tensors in
    //     __dupN noise. The canonical node with a real layer suffix is the
    //     boundary we want.
    if (raw.find("(view)") != std::string::npos) return true;

    const char* boundary = MatchBoundary(raw);
    if (!boundary) return true;

    const int layer = ExtractLayer(raw);
    if (layer < 0) return true;          // unlayered nodes are not boundaries
    if (g_max_layer >= 0 && layer > g_max_layer) return true;

    const int64_t ne0 = t->ne[0];
    const int64_t ne1 = t->ne[1];
    const int64_t ne2 = t->ne[2];
    const int64_t ne3 = t->ne[3];
    const int64_t elems = ggml_nelements(t);
    if (elems <= 0) return true;

    // Reject absurdly large nodes: the vocabulary logits tensor is exported
    // explicitly, and anything else this big is not a layer boundary.
    if (elems > (int64_t) 256 * 1024 * 1024) return true;

    Dump d;
    d.boundary = boundary;
    d.raw_name = raw;
    d.layer    = layer;
    d.ne[0] = ne0; d.ne[1] = ne1; d.ne[2] = ne2; d.ne[3] = ne3;
    d.elems    = elems;
    d.data.resize((size_t) elems);
    std::memcpy(d.data.data(), t->data, (size_t) elems * sizeof(float));

    std::lock_guard<std::mutex> lk(g_mu);
    g_dumps.push_back(std::move(d));
    return true;
}

// Last writer wins per (layer, boundary). When a boundary appears more than
// once for the same layer (different graph stages / aliases) the later node is
// the one that survives to the residual stream, which is what we compare.
std::string Disambiguate(const std::string& base,
                         const std::unordered_map<std::string, int>& seen) {
    auto it = seen.find(base);
    if (it == seen.end()) return base;
    return base + "__dup" + std::to_string(it->second);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::fprintf(stderr,
            "usage: %s <model.gguf> <tokens_file> <output_dir> "
            "[--max-layer N] [--no-hidden] [--no-logits]\n", argv[0]);
        return 1;
    }

    const char* model_path  = argv[1];
    const char* tokens_file = argv[2];
    g_out_dir = argv[3];

    bool want_hidden = true;
    bool want_logits = true;
    for (int i = 4; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--max-layer" && i + 1 < argc) {
            g_max_layer = std::atoi(argv[++i]);
        } else if (a == "--no-hidden") {
            want_hidden = false;
        } else if (a == "--no-logits") {
            want_logits = false;
        } else {
            std::fprintf(stderr, "unknown arg %s\n", a.c_str());
            return 1;
        }
    }

    // ---- tokens -----------------------------------------------------------
    std::vector<llama_token> tokens;
    if (FILE* tf = std::fopen(tokens_file, "r")) {
        int v = 0;
        while (std::fscanf(tf, "%d", &v) == 1) tokens.push_back((llama_token) v);
        std::fclose(tf);
    } else {
        std::fprintf(stderr, "cannot open tokens file: %s\n", tokens_file);
        return 1;
    }
    if (tokens.empty()) {
        std::fprintf(stderr, "no tokens in %s\n", tokens_file);
        return 1;
    }
    std::printf("tokens: %zu (first=%d last=%d)\n", tokens.size(),
                (int) tokens.front(), (int) tokens.back());

    // ---- model ------------------------------------------------------------
    llama_backend_init();

    llama_model_params mp = llama_model_default_params();
    mp.n_gpu_layers = 0;                      // CPU: node data is host-valid

    llama_model* model = llama_model_load_from_file(model_path, mp);
    if (!model) {
        std::fprintf(stderr, "model load failed: %s\n", model_path);
        return 2;
    }

    // (3) dimensions come from the model, never from a constant.
    g_n_embd  = llama_model_n_embd(model);
    const llama_vocab* vocab = llama_model_get_vocab(model);
    g_n_vocab = vocab ? llama_vocab_n_tokens(vocab) : 0;
    const int n_layer = llama_model_n_layer(model);

    std::printf("model: n_embd=%d n_vocab=%d n_layer=%d\n",
                g_n_embd, g_n_vocab, n_layer);
    if (g_n_embd <= 0 || g_n_vocab <= 0) {
        std::fprintf(stderr, "model reported invalid geometry\n");
        return 3;
    }

    // ---- context ----------------------------------------------------------
    llama_context_params cp = llama_context_default_params();
    cp.n_ctx       = (uint32_t) (tokens.size() > 1024 ? tokens.size() : 1024);
    cp.n_batch     = (uint32_t) (tokens.size() > 1024 ? tokens.size() : 1024);
    cp.embeddings  = true;                    // required for embeddings_ith
    cp.cb_eval     = GraphNodeCallback;
    cp.cb_eval_user_data = nullptr;

    llama_context* ctx = llama_init_from_model(model, cp);
    if (!ctx) {
        std::fprintf(stderr, "context creation failed\n");
        return 4;
    }

    std::error_code ec;
    fs::create_directories(fs::path(g_out_dir), ec);

    // ---- per-position capture --------------------------------------------
    for (size_t pos = 0; pos < tokens.size(); ++pos) {
        g_pos = (int) pos;
        {
            std::lock_guard<std::mutex> lk(g_mu);
            g_dumps.clear();
        }

        llama_batch batch = llama_batch_init(1, 0, 1);
        if (!batch.token) {
            std::fprintf(stderr, "llama_batch_init failed at pos %zu\n", pos);
            return 5;
        }
        batch.n_tokens   = 1;
        batch.token[0]   = tokens[pos];
        batch.pos[0]     = (llama_pos) pos;
        batch.n_seq_id[0] = 1;
        batch.seq_id[0][0] = 0;
        batch.logits[0]  = 1;

        if (llama_decode(ctx, batch) != 0) {
            std::fprintf(stderr, "llama_decode failed at pos %zu\n", pos);
            llama_batch_free(batch);
            return 6;
        }

        std::vector<Dump> captured;
        {
            std::lock_guard<std::mutex> lk(g_mu);
            captured.swap(g_dumps);
        }

        // ---- M9: synthesize resid_in per layer -----------------------------
        // The residual stream entering layer L is exactly the block output of
        // layer L-1 (l_out / resid2): llama.cpp sets inpL = cur at the end of
        // each block. The block-input node itself is unnamed in the vendored
        // deepseek2 graph, so we chain resid2_{L-1} -> resid_in_L here. Layer-0
        // residual is the token embedding (token_embd) when the graph names it.
        {
            std::unordered_map<int, Dump> resid2_by_layer;
            int max_l = -1;
            for (const auto& d : captured) {
                if (d.boundary == "resid2") resid2_by_layer[d.layer] = d;
                if (d.layer > max_l) max_l = d.layer;
            }
            std::vector<Dump> synth;
            for (int L = 1; L <= max_l; ++L) {
                auto it = resid2_by_layer.find(L - 1);
                if (it == resid2_by_layer.end()) continue;
                Dump d;
                d.boundary = "resid_in";
                d.raw_name = "derived:resid2_" + std::to_string(L - 1);
                d.layer    = L;
                d.ne[0] = it->second.ne[0]; d.ne[1] = it->second.ne[1];
                d.ne[2] = it->second.ne[2]; d.ne[3] = it->second.ne[3];
                d.elems    = it->second.elems;
                d.data     = it->second.data;
                synth.push_back(std::move(d));
            }
            for (const auto& d : captured) {
                if (d.boundary == "token_embd" && d.layer == 0) {
                    Dump d0 = d;
                    d0.boundary = "resid_in";
                    d0.raw_name = "derived:token_embd";
                    d0.layer = 0;
                    synth.push_back(std::move(d0));
                    break;
                }
            }
            captured.insert(captured.end(), synth.begin(), synth.end());
        }

        char dirbuf[64];
        std::snprintf(dirbuf, sizeof(dirbuf), "pos%zu", pos);
        const fs::path dir = fs::path(g_out_dir) / dirbuf;
        fs::create_directories(dir, ec);

        // Manifest. Shape is recorded so an alignment step can prove that the
        // reference and native tensors describe the same elements.
        std::string manifest;
        manifest += "# boundary raw_name layer ne0 ne1 ne2 ne3 elems bytes\n";

        std::unordered_map<std::string, int> seen;
        int written = 0;
        for (auto& d : captured) {
            // Skip the global logits tensor here; it is written explicitly.
            if (d.boundary == "logits") continue;

            const std::string key =
                d.boundary + "_L" + std::to_string(d.layer);
            const std::string fname = Disambiguate(key, seen) + ".bin";
            seen[key]++;

            const fs::path out = dir / fname;
            FILE* f = std::fopen(out.string().c_str(), "wb");
            if (!f) {
                std::fprintf(stderr, "cannot write %s\n", out.string().c_str());
                continue;
            }
            const size_t n = (size_t) d.elems;
            const size_t w = std::fwrite(d.data.data(), sizeof(float), n, f);
            std::fclose(f);
            if (w != n) {
                std::fprintf(stderr, "short write on %s\n", out.string().c_str());
                continue;
            }

            char line[512];
            std::snprintf(line, sizeof(line),
                          "%s %s %d %lld %lld %lld %lld %lld %lld\n",
                          fname.c_str(), d.raw_name.c_str(), d.layer,
                          (long long) d.ne[0], (long long) d.ne[1],
                          (long long) d.ne[2], (long long) d.ne[3],
                          (long long) d.elems, (long long) (n * sizeof(float)));
            manifest += line;
            ++written;
        }
        if (FILE* mf = std::fopen((dir / "manifest.txt").string().c_str(), "wb")) {
            std::fwrite(manifest.data(), 1, manifest.size(), mf);
            std::fclose(mf);
        }

        // ---- logits ------------------------------------------------------
        if (want_logits) {
            const float* logits = llama_get_logits_ith(ctx, 0);
            if (!logits) {
                std::fprintf(stderr, "get_logits_ith null at pos %zu\n", pos);
            } else {
                const fs::path out = dir / "logits.bin";
                if (FILE* f = std::fopen(out.string().c_str(), "wb")) {
                    const size_t w = std::fwrite(logits, sizeof(float),
                                                 (size_t) g_n_vocab, f);
                    std::fclose(f);
                    if (w != (size_t) g_n_vocab)
                        std::fprintf(stderr, "short logits write pos %zu\n", pos);
                }
            }
        }

        // ---- final hidden ------------------------------------------------
        if (want_hidden) {
            const float* hid = llama_get_embeddings_ith(ctx, 0);
            if (!hid) {
                std::fprintf(stderr, "get_embeddings_ith null at pos %zu\n", pos);
            } else {
                const fs::path out = dir / "final_hidden.bin";
                if (FILE* f = std::fopen(out.string().c_str(), "wb")) {
                    const size_t w = std::fwrite(hid, sizeof(float),
                                                 (size_t) g_n_embd, f);
                    std::fclose(f);
                    if (w != (size_t) g_n_embd)
                        std::fprintf(stderr, "short hidden write pos %zu\n", pos);
                }
            }
        }

        std::printf("pos %zu: %d boundary tensors\n", pos, written);
        llama_batch_free(batch);
    }

    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}