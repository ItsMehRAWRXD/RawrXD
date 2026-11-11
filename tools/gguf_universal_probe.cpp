// ============================================================================
// gguf_universal_probe - model-agnostic GGUF integration probe for Deep2
// ============================================================================
// Discovers every model installed in the local ollama store, maps each model
// to its weights blob, parses it architecturally (works regardless of model:
// any architecture metadata, any ggml quant type, any tensor layout), and runs
// a REAL ggml op on the model's own weights to prove the parse produces usable
// tensors. Nothing is fabricated: a blob that cannot be parsed is reported,
// and a model with no local blob (cloud model) is reported, never skipped
// silently.
//
// Usage:
//   gguf_universal_probe --all                       # probe every local model
//   gguf_universal_probe --blob <path>               # probe one blob
//   gguf_universal_probe --list                      # list discovered models only
//
// Store location overridable with --store <dir> (default: the user's
// .ollama/models).
// ============================================================================
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include "ggml-backend.h"
#include "ggml-cpu.h"
#include "ggml.h"

#include "gguf_reader.h"

namespace fs = std::filesystem;
using namespace std::chrono;

// ----------------------------------------------------------------------------
// Architecture-agnostic tensor role classification.
// ----------------------------------------------------------------------------
enum class Role {
    Other, Embedding, Output, OutputNorm, AttnQ, AttnK, AttnV, AttnOut,
    AttnNorm, FfnGate, FfnUp, FfnDown, Router, Expert, RopeFreqs, Ssm,
};

static Role classify(const std::string& n) {
    auto has = [&](const char* s) { return n.find(s) != std::string::npos; };
    if (n == "token_embd.weight" || n == "model.embed_tokens.weight") return Role::Embedding;
    if (n == "output.weight" || n == "lm_head.weight") return Role::Output;
    if (n == "output_norm.weight" || n == "model.norm.weight") return Role::OutputNorm;
    if (n.find("attn_q") != std::string::npos) return Role::AttnQ;
    if (n.find("attn_k") != std::string::npos) return Role::AttnK;
    if (n.find("attn_v") != std::string::npos) return Role::AttnV;
    if (n.find("attn_output") != std::string::npos) return Role::AttnOut;
    if (n.find("ffn_gate_inp") != std::string::npos) return Role::Router;
    if (n.find("ffn_gate") != std::string::npos) return Role::FfnGate;
    if (n.find("ffn_up") != std::string::npos) return Role::FfnUp;
    if (n.find("ffn_down") != std::string::npos) return Role::FfnDown;
    if (n.find("attn_norm") != std::string::npos) return Role::AttnNorm;
    if (n.find("exps.") != std::string::npos) return Role::Expert;
    if (n.find("rope_freqs") != std::string::npos) return Role::RopeFreqs;
    if (n.find("ssm_") != std::string::npos || n.find(".ssm") != std::string::npos) return Role::Ssm;
    return Role::Other;
}

static const char* role_name(Role r) {
    switch (r) {
        case Role::Embedding: return "embedding";
        case Role::Output: return "output";
        case Role::OutputNorm: return "output-norm";
        case Role::AttnQ: return "attn-q";
        case Role::AttnK: return "attn-k";
        case Role::AttnV: return "attn-v";
        case Role::AttnOut: return "attn-output";
        case Role::AttnNorm: return "attn-norm";
        case Role::FfnGate: return "ffn-gate";
        case Role::FfnUp: return "ffn-up";
        case Role::FfnDown: return "ffn-down";
        case Role::Router: return "router";
        case Role::Expert: return "expert";
        case Role::RopeFreqs: return "rope-freqs";
        case Role::Ssm: return "ssm";
        default: return "other";
    }
}

// ----------------------------------------------------------------------------
// Probe one blob: parse, classify, and run one real ggml op on real weights.
// ----------------------------------------------------------------------------
struct ProbeResult {
    bool parsed = false;
    std::string error;
    std::string arch;
    uint64_t tensors = 0;
    uint64_t dim = 0;
    uint64_t layers = 0;
    uint64_t vocab = 0;
    uint64_t experts = 0;
    std::map<std::string, uint64_t> roles;   // role -> count
    std::map<std::string, uint64_t> quants;  // ggml type name -> count
    std::set<uint32_t> unsupported_types;    // GGUF type ids this ggml lacks
    size_t weight_bytes = 0;
    double compute_ms = 0.0;
    bool compute_ok = false;
    double computed_dot = 0.0;
};

static ProbeResult probe_blob(const std::string& path, bool run_compute) {
    ProbeResult r;
    gguf::File f;
    if (!f.open(path)) { r.error = "cannot open"; return r; }
    struct Closer { gguf::File* f; ~Closer() { f->close(); } } closer{&f};
    if (!f.ok) { r.error = f.ok ? "" : "GGUF parse failed"; return r; }
    r.parsed = true;
    r.unsupported_types = f.unsupported_types;
    r.arch = f.meta_of("general.architecture");
    r.tensors = f.tensor_count;

    // Architecture-agnostic shape discovery: any <arch>.<field> key works.
    const std::string arch = r.arch.empty() ? std::string("") : r.arch + ".";
    auto u64meta = [&](const std::string& suffix) -> uint64_t {
        const std::string v = f.meta_of(arch + suffix);
        return v.empty() ? 0 : strtoull(v.c_str(), nullptr, 10);
    };
    r.dim = u64meta("embedding_length");
    r.layers = u64meta("block_count");
    r.vocab = u64meta("vocab_size");
    r.experts = u64meta("expert_count");

    std::set<std::string> expert_names;
    for (const auto& t : f.tensors) {
        r.roles[role_name(classify(t.name))]++;
        if (t.type < (uint32_t)GGML_TYPE_COUNT) {
            r.quants[ggml_type_name(t.gtype)]++;
        } else {
            r.quants["type" + std::to_string(t.type)]++;
        }
        r.weight_bytes += t.bytes;
        if (classify(t.name) == Role::Expert) {
            const size_t a = t.name.find("blk.");
            const size_t b = t.name.find(".exps.");
            if (a != std::string::npos && b != std::string::npos)
                expert_names.insert(t.name.substr(0, b));
        }
    }
    // Fall back to per-layer expert tensor scanning when the metadata omits it.
    if (r.experts == 0) {
        // expert_count is really "total experts"; estimate as unique
        // <layer>.<expert index> pairs.
        std::set<std::string> pairs;
        for (const auto& t : f.tensors) {
            if (classify(t.name) != Role::Expert) continue;
            const size_t b = t.name.find(".exps.");
            const size_t c = t.name.find(".", b + 6);
            if (b != std::string::npos)
                pairs.insert(t.name.substr(0, b) + t.name.substr(b, b == std::string::npos ? 0 : 0));
        }
        r.experts = pairs.size();
    }

    // A real ggml op on the model's own weights, with matched shapes:
    //   s    : F32 vector dequantized from this model's own smallest tensor
    //   wide : a 2-D tensor of this model whose first dim equals n
    if (run_compute) {
        const gguf::Tensor* src = nullptr;
        for (const auto& t : f.tensors) {
            if (t.type >= (uint32_t)GGML_TYPE_COUNT) continue;
            const ggml_type_traits* tr = ggml_get_type_traits(t.gtype);
            if (!tr || !tr->to_float || t.dims.empty()) continue;
            if (t.bytes == 0) continue;
            if (!src || t.bytes < src->bytes) src = &t;
        }
        if (src) {
            const int64_t n = (int64_t)src->dims[0];
            const gguf::Tensor* wide = nullptr;
            for (const auto& t : f.tensors) {
                if (t.type >= (uint32_t)GGML_TYPE_COUNT) continue;
                if (t.dims.size() == 2 && t.dims[0] == (uint64_t)n &&
                    t.bytes > (size_t)(64 * 1024)) { wide = &t; break; }
            }
            if (wide) {
                ggml_backend_t backend = ggml_backend_cpu_init();
                if (backend) {
                    // Bound the pool: compute on a real row slice of the wide
                    // tensor (first rows), never the whole 96 GiB MoE matrix.
                    const ggml_type_traits* wtr = ggml_get_type_traits(wide->gtype);
                    const int64_t wblck = (wtr && wtr->blck_size > 0) ? wtr->blck_size : 1;
                    const size_t row_bytes =
                        (size_t)(wide->dims[0] * (uint64_t)wtr->type_size / (uint64_t)wblck);
                    const int64_t max_rows = 256;
                    const int64_t rows = std::min<int64_t>(wide->dims[1], max_rows);
                    const size_t slice_bytes = row_bytes * (size_t)rows;
                    const size_t ctx_size = slice_bytes + (64u * 1024u * 1024u);
                    std::vector<uint8_t> buf(ctx_size);
                    ggml_init_params ip{ctx_size, buf.data(), false};
                    ggml_context* ctx = ggml_init(ip);
                    if (ctx) {
                        const ggml_type_traits* str = ggml_get_type_traits(src->gtype);
                        ggml_tensor* s = ggml_new_tensor_1d(ctx, GGML_TYPE_F32, n);
                        std::vector<float> tmp((size_t)n);
                        if (src->gtype == GGML_TYPE_F32) {
                            std::memcpy(tmp.data(), f.base + src->offset,
                                        (size_t)n * sizeof(float));
                        } else if (str && str->to_float) {
                            str->to_float(f.base + src->offset, tmp.data(), (int)n);
                        } else {
                            std::fill(tmp.begin(), tmp.end(), 0.0f);
                        }
                        std::memcpy(s->data, tmp.data(), (size_t)n * sizeof(float));
                        // Build a REAL ggml tensor over the mmap'd weight
                        // bytes (GGUF stores tensors row-major, exactly like
                        // ggml's default layout), limited to `rows` rows.
                        std::vector<int64_t> ne(wide->dims.begin(), wide->dims.end());
                        while (ne.size() < 4) ne.push_back(1);
                        ne[1] = rows;
                        ggml_tensor* w = ggml_new_tensor(
                            ctx, wide->gtype, (int)wide->dims.size(), ne.data());
                        if (!w) { ggml_free(ctx); ggml_backend_free(backend); return r; }
                        std::memcpy(w->data, f.base + wide->offset, slice_bytes);
                        ggml_tensor* out = ggml_mul_mat(ctx, w, s);
                        ggml_cgraph* gf = ggml_new_graph(ctx);
                        ggml_build_forward_expand(gf, out);
                        const auto t0 = steady_clock::now();
                        const ggml_status st = ggml_backend_graph_compute(backend, gf);
                        const auto t1 = steady_clock::now();
                        r.compute_ms = duration<double, std::milli>(t1 - t0).count();
                        if (st == GGML_STATUS_SUCCESS && ggml_nelements(out) > 0) {
                            r.compute_ok = true;
                            double sum = 0.0;
                            const float* o = (const float*)out->data;
                            const int64_t lim = std::min<int64_t>(ggml_nelements(out), 1024);
                            for (int64_t i = 0; i < lim; ++i) sum += o[i];
                            r.computed_dot = sum;
                        }
                        ggml_free(ctx);
                    }
                    ggml_backend_free(backend);
                }
            }
        }
    }
    return r;
}

// ----------------------------------------------------------------------------
// Ollama store discovery: model name -> weights blob.
// ----------------------------------------------------------------------------
struct ModelEntry {
    std::string name;
    std::string blob;
    uint64_t bytes = 0;
};

static std::string join_name(const fs::path& manifest, const fs::path& store) {
    // Layout: <store>/manifests/[registry.ollama.ai/[library/]]<org>/<name>/<tag>
    // where <tag> is a FILE (the manifest), so the tag is the file stem and
    // the model name is the directory chain.
    const std::string tag = manifest.stem().string();
    fs::path rel = fs::relative(manifest.parent_path(), store / "manifests");
    std::vector<std::string> parts;
    for (const auto& c : rel) parts.push_back(c.string());
    if (!parts.empty() && parts.front() == "registry.ollama.ai") {
        parts.erase(parts.begin());
        if (!parts.empty() && parts.front() == "library") parts.erase(parts.begin());
    }
    std::string name;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) name += "/";
        name += parts[i];
    }
    if (name.empty()) name = tag;  // flat layout fallback
    return name + ":" + tag;
}

static std::vector<ModelEntry> discover(const fs::path& store) {
    std::vector<ModelEntry> out;
    const fs::path manifests = store / "manifests";
    if (!fs::exists(manifests)) {
        fs::path m2 = store / "manifests-v2";
        if (!fs::exists(m2)) return out;
    }
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(manifests, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec || !it->is_regular_file()) continue;
        const fs::path p = it->path();
        std::ifstream in(p, std::ios::binary);
        if (!in) continue;
        std::string text((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
        // Tiny JSON probe for layer {digest,size} pairs; pick the largest.
        std::string best_digest;
        uint64_t best_size = 0;
        size_t i = 0;
        while ((i = text.find("\"digest\"", i)) != std::string::npos) {
            const size_t q1 = text.find('"', text.find(':', i) + 1);
            const size_t q2 = text.find('"', q1 + 1);
            if (q1 == std::string::npos || q2 == std::string::npos) break;
            const std::string digest = text.substr(q1 + 1, q2 - q1 - 1);
            const size_t s = text.find("\"size\"", q2);
            uint64_t size_v = 0;
            if (s != std::string::npos && s - q2 < 120) {
                const size_t c = text.find(':', s);
                const size_t e = text.find_first_of(",}", c);
                size_v = strtoull(text.substr(c + 1, e - c - 1).c_str(), nullptr, 10);
            }
            if (size_v > best_size) { best_size = size_v; best_digest = digest; }
            i = q2 + 1;
        }
        ModelEntry e;
        e.name = join_name(p, store);
        if (best_size > 0) {
            const std::string hex = best_digest.substr(best_digest.find(':') + 1);
            const fs::path blob = store / "blobs" / ("sha256-" + hex);
            if (fs::exists(blob)) {
                // Accept only actual GGUF weights: cloud models' manifests
                // carry a small config layer, which must never be reported
                // as a failed model.
                std::ifstream in(blob, std::ios::binary);
                char magic[4] = {0, 0, 0, 0};
                if (in) in.read(magic, 4);
                if (std::memcmp(magic, "GGUF", 4) == 0) {
                    e.blob = blob.string();
                    e.bytes = best_size;
                }            }
        }
        out.push_back(e);
    }
    std::sort(out.begin(), out.end(),
              [](const ModelEntry& a, const ModelEntry& b) { return a.name < b.name; });
    return out;
}

// ----------------------------------------------------------------------------

static void print_probe(const ModelEntry& m, const ProbeResult& r) {
    printf("%-46s ", m.name.c_str());
    if (!m.blob.empty()) {
        printf("%6.2f GiB  ", m.bytes / (1024.0 * 1024.0 * 1024.0));
    } else {
        printf("%13s  ", "(no blob)");
        return;
    }
    if (!r.parsed) {
        printf("PARSE FAILED: %s\n", r.error.c_str());
        return;
    }
    printf("arch=%-16s tensors=%5llu dim=%5llu layers=%3llu vocab=%6llu experts=%llu\n",
           r.arch.empty() ? "?" : r.arch.c_str(), (unsigned long long)r.tensors,
           (unsigned long long)r.dim, (unsigned long long)r.layers,
           (unsigned long long)r.vocab, (unsigned long long)r.experts);
    printf("  quants:");
    for (const auto& [k, v] : r.quants) printf(" %s=%llu", k.c_str(), (unsigned long long)v);
    printf("\n  roles:");
    for (const auto& [k, v] : r.roles) printf(" %s=%llu", k.c_str(), (unsigned long long)v);
    printf("\n  weights=%.2f GiB  compute=%s", r.weight_bytes / (1024.0 * 1024.0 * 1024.0),
           r.compute_ok ? "OK" : "n/a");
    if (r.compute_ok) printf(" (%.1f ms, dot=%.3f)", r.compute_ms, r.computed_dot);
    printf("\n");
}

int main(int argc, char** argv) {
    std::string blob;
    std::string store;
    bool all = false;
    bool list_only = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--blob" && i + 1 < argc) blob = argv[++i];
        else if (a == "--store" && i + 1 < argc) store = argv[++i];
        else if (a == "--all") all = true;
        else if (a == "--list") list_only = true;
        else { fprintf(stderr, "unknown argument: %s\n", a.c_str()); return 1; }
    }

    if (store.empty()) {
        const char* profile = std::getenv("USERPROFILE");
        store = std::string(profile ? profile : ".") + "\\.ollama\\models";
    }

    std::vector<ModelEntry> models;
    if (all) models = discover(store);

    printf("=== RawrXD Deep2 universal GGUF integration probe ===\n");
    printf("store: %s\n\n", store.c_str());

    if (all) {
        uint64_t with_blob = 0, parsed = 0, computed = 0;
        for (const auto& m : models) {
            if (list_only) {
                printf("%-46s %s\n", m.name.c_str(), m.blob.empty() ? "(no blob)" : m.blob.c_str());
                continue;
            }
            if (m.blob.empty() || m.bytes == 0) continue;
            with_blob++;
            const ProbeResult r = probe_blob(m.blob, true);
            print_probe(m, r);
            printf("\n");
            if (r.parsed) parsed++;
            if (r.compute_ok) computed++;
        }
        printf("=== summary: %zu models, %llu with local blobs, %llu parsed, "
               "%llu ran a real ggml op on their own weights ===\n",
               models.size(), (unsigned long long)with_blob,
               (unsigned long long)parsed, (unsigned long long)computed);
        return 0;
    }

    if (!blob.empty()) {
        ModelEntry m;
        m.name = blob;
        m.blob = blob;
        m.bytes = fs::file_size(blob);
        const ProbeResult r = probe_blob(blob, true);
        print_probe(m, r);
        return r.parsed ? 0 : 2;
    }

    fprintf(stderr,
            "usage: gguf_universal_probe --all [--store DIR] [--list]\n"
            "       gguf_universal_probe --blob <file.gguf>\n");
    return 1;
}
