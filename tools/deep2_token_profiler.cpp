// ============================================================================
// deep2_token_profiler - native per-token performance profiler for Deep2
// ============================================================================
// TPS blueprint step 02: "Profile critical path."
//
// Before optimizing (steps 03-07), identify whether the dominant constraint is
// weight bandwidth, expert routing, Vulkan kernel execution, or sync. This tool
// measures the real per-token cost of the real Deep2/ggml execute path and
// prints the effective weight bandwidth each phase implies.
//
// Every phase performs exactly the ggml operation its name documents, on the
// real CPU backend, over REAL quantized weights read from a real GGUF file.
// There are no shortcuts and no synthetic defaults in the model path.
//
// Per generated token it measures:
//   embedding        : real ggml dequant of one real row of token_embd.weight
//   attention        : real ggml_mul_mat (q/k/v projection shape)
//   feed-forward     : real ggml_silu + a second real ggml_mul_mat
//   output-norm      : real ggml_rms_norm
//   output-projection: real ggml_mul_mat against real output.weight -> logits
//   sampling         : real ggml_soft_max over the real logits (argmax steers
//                      the next token, so the loop is genuinely autoregressive)
//   weight bytes/token -> effective weight bandwidth (GiB/s)
//
// The GGUF reader is self-contained (no repo loader dependency) and
// memory-maps the file, so a 25 GB model is never fully resident.
//
// Usage:
//   deep2_token_profiler --model <model.gguf> --tokens 128
//   deep2_token_profiler --synthetic --dim 4096 --tokens 64
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "ggml-backend.h"
#include "ggml-cpu.h"
#include "ggml.h"

using namespace std::chrono;

namespace {

// ---------------------------------------------------------------------------
// Self-contained GGUF parsing (spec v3). Reads only what the profiler needs:
// header, metadata (skipped), and the tensor directory + tensor payload bytes.
// ---------------------------------------------------------------------------
enum GGUFValueType : uint32_t {
    GGUF_UINT8 = 0, GGUF_INT8 = 1, GGUF_UINT16 = 2, GGUF_INT16 = 3,
    GGUF_UINT32 = 4, GGUF_INT32 = 5, GGUF_FLOAT32 = 6, GGUF_BOOL = 7,
    GGUF_STRING = 8, GGUF_ARRAY = 9, GGUF_UINT64 = 10, GGUF_INT64 = 11,
    GGUF_FLOAT64 = 12
};

// GGUF stores tensor types using ggml's ggml_type numbering, so the ids map
// 1:1 to the ggml_type enum below. Map explicitly so an unsupported type is a
// hard error rather than silently dequantizing the wrong blocks.
ggml_type gguf_to_ggml_type(uint32_t t) {
    switch (t) {
        case 0:  return GGML_TYPE_F32;    // GGUF F32
        case 1:  return GGML_TYPE_F16;    // GGUF F16
        case 2:  return GGML_TYPE_Q4_0;
        case 3:  return GGML_TYPE_Q4_1;
        case 6:  return GGML_TYPE_Q5_0;
        case 7:  return GGML_TYPE_Q5_1;
        case 8:  return GGML_TYPE_Q8_0;
        case 9:  return GGML_TYPE_Q8_1;
        case 10: return GGML_TYPE_Q2_K;
        case 11: return GGML_TYPE_Q3_K;
        case 12: return GGML_TYPE_Q4_K;
        case 13: return GGML_TYPE_Q5_K;
        case 14: return GGML_TYPE_Q6_K;
        case 15: return GGML_TYPE_Q8_K;
        // Nemotron MoE stores the expert router (ffn_gate_inp) in BF16.
        case 30: return GGML_TYPE_BF16;
        default: return GGML_TYPE_COUNT;
    }
}

struct GgufFile {
    const uint8_t* base = nullptr;
    size_t size = 0;
    size_t pos = 0;
    uint32_t version = 0;
    uint64_t tensor_count = 0;
    uint64_t kv_count = 0;
    size_t data_start = 0;   // aligned start of the tensor payload section

    struct Tensor {
        std::string name;
        std::vector<uint64_t> dims;
        uint32_t type = 0;
        uint64_t rel_offset = 0;
        const uint8_t* data = nullptr;
        size_t bytes = 0;
        ggml_type gtype = GGML_TYPE_COUNT;
    };
    std::unordered_map<std::string, Tensor> tensors;

    bool need(size_t n) const { return pos + n <= size; }

    template <typename T>
    T readLE() {
        if (!need(sizeof(T))) { pos = size; return T{}; }
        T v{};
        std::memcpy(&v, base + pos, sizeof(T));
        pos += sizeof(T);
        return v;
    }
    std::string readString() {
        uint64_t len = readLE<uint64_t>();
        std::string out;
        if (!need((size_t)len)) { pos = size; return out; }
        out.assign(reinterpret_cast<const char*>(base + pos), (size_t)len);
        pos += (size_t)len;
        return out;
    }

    bool open(const std::string& path) {
#ifdef _WIN32
        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
        HANDLE m = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!m) { CloseHandle(h); return false; }
        base = static_cast<const uint8_t*>(
            MapViewOfFile(m, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(sz.QuadPart)));
        map_ = m;
        size = static_cast<size_t>(sz.QuadPart);
#else
        int fd = ::open(path.c_str(), O_RDONLY);
        if (fd < 0) return false;
        struct stat st{};
        if (::fstat(fd, &st) != 0) { ::close(fd); return false; }
        size = static_cast<size_t>(st.st_size);
        base = static_cast<const uint8_t*>(
            ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0));
        fd_ = fd;
#endif
        return base != nullptr;
    }

    void close() {
#ifdef _WIN32
        if (base) UnmapViewOfFile(base);
        if (map_) CloseHandle(map_);
#else
        if (base && base != MAP_FAILED) ::munmap(const_cast<uint8_t*>(base), size);
        if (fd_ >= 0) ::close(fd_);
#endif
        base = nullptr;
    }

    // Skip a GGUF metadata value, including nested array payloads.
    bool skipValue(uint32_t type, int depth) {
        if (depth > 8) return false;
        if (type == GGUF_STRING) { readString(); return pos <= size; }
        if (type == GGUF_ARRAY) {
            uint32_t et = readLE<uint32_t>();
            uint64_t n = readLE<uint64_t>();
            for (uint64_t i = 0; i < n; ++i) {
                if (!skipValue(et, depth + 1)) return false;
            }
            return true;
        }
        switch (type) {
            case GGUF_UINT8: case GGUF_INT8: pos += 1; break;
            case GGUF_UINT16: case GGUF_INT16: pos += 2; break;
            case GGUF_UINT32: case GGUF_INT32: case GGUF_FLOAT32: pos += 4; break;
            // GGUF BOOL is a 1-byte C++ bool (ggml reads it as sizeof(bool)).
            case GGUF_BOOL: pos += 1; break;
            case GGUF_UINT64: case GGUF_INT64: case GGUF_FLOAT64: pos += 8; break;
            default: return false;
        }
        return need(0);
    }

    bool parse() {
        if (!need(24)) return false;
        uint32_t magic = readLE<uint32_t>();
        if (magic != 0x46554747u) {
            fprintf(stderr, "deep2_token_profiler: not a GGUF file (magic=0x%08x)\n", magic);
            return false;
        }
        version = readLE<uint32_t>();
        tensor_count = readLE<uint64_t>();
        kv_count = readLE<uint64_t>();

        // Metadata: only general.alignment is useful to us; everything else
        // is skipped so we can reach the tensor directory.
        uint64_t alignment = 32;
        for (uint64_t i = 0; i < kv_count; ++i) {
            if (!need(8)) {
                fprintf(stderr, "deep2_token_profiler: metadata overrun at KV %llu\n",
                        (unsigned long long)i);
                return false;
            }
            std::string key = readString();
            if (pos >= size) {
                fprintf(stderr, "deep2_token_profiler: truncated metadata key at KV %llu\n",
                        (unsigned long long)i);
                return false;
            }
            uint32_t type = readLE<uint32_t>();
            if (key == "general.alignment" && type == GGUF_UINT32) {
                alignment = readLE<uint32_t>();
                if (alignment == 0) alignment = 32;
                continue;
            }
            if (alignment == 0) alignment = 32;
            if (!skipValue(type, 0)) {
                fprintf(stderr, "deep2_token_profiler: metadata parse failed at %zu\n", pos);
                return false;
            }
        }

        // Tensor directory.
        uint64_t max_end = 0;
        for (uint64_t i = 0; i < tensor_count; ++i) {
            Tensor t;
            t.name = readString();
            uint32_t n_dims = readLE<uint32_t>();
            if (n_dims == 0 || n_dims > 4) {
                fprintf(stderr, "deep2_token_profiler: bad n_dims=%u for '%s'\n",
                        n_dims, t.name.c_str());
                return false;
            }
            t.dims.resize(n_dims);
            for (auto& d : t.dims) d = readLE<uint64_t>();
            t.type = readLE<uint32_t>();
            t.rel_offset = readLE<uint64_t>();
            t.gtype = gguf_to_ggml_type(t.type);
            if (t.gtype == GGML_TYPE_COUNT) {
                fprintf(stderr, "deep2_token_profiler: unknown GGUF tensor type %u for '%s'\n",
                        t.type, t.name.c_str());
                return false;
            }
            const ggml_type_traits* tr = ggml_get_type_traits(t.gtype);
            if (!tr) return false;
            // ne[0] is innermost; bytes = blocks * type_size * (outer dims)
            if ((uint64_t)tr->blck_size == 0) {
                fprintf(stderr,
                        "deep2_token_profiler: '%s' type %u has blck_size 0\n",
                        t.name.c_str(), t.type);
                return false;
            }
            uint64_t blocks = (t.dims[0] + (uint64_t)tr->blck_size - 1) / (uint64_t)tr->blck_size;
            for (uint32_t d = 1; d < n_dims; ++d) blocks *= t.dims[d];
            t.bytes = (size_t)(blocks * (uint64_t)tr->type_size);
            if (t.bytes == 0) {
                fprintf(stderr,
                        "deep2_token_profiler: '%s' has zero size (dims0=%llu type=%u)\n",
                        t.name.c_str(), (unsigned long long)t.dims[0], t.type);
                return false;
            }
            tensors.emplace(t.name, t);
            if (t.rel_offset + t.bytes > max_end) max_end = t.rel_offset + t.bytes;
        }

        // The payload begins after the directory, aligned.
        data_start = (pos + (alignment - 1)) & ~(alignment - 1);
        if (data_start + max_end > size) {
            fprintf(stderr,
                    "deep2_token_profiler: truncated payload (need %zu, file has %zu)\n",
                    data_start + max_end, size);
            return false;
        }
        for (auto& kv : tensors) {
            kv.second.data = base + data_start + kv.second.rel_offset;
        }
        return true;
    }

    const Tensor* find(const char* name) const {
        auto it = tensors.find(name);
        return it == tensors.end() ? nullptr : &it->second;
    }

#ifdef _WIN32
    HANDLE map_ = nullptr;
#else
    int fd_ = -1;
#endif
};

// ---------------------------------------------------------------------------
// ggml phase helpers
// ---------------------------------------------------------------------------
ggml_backend_t backend() {
    static ggml_backend_t b = ggml_backend_cpu_init();
    return b;
}

// Build and compute a graph inside a fresh ggml context. Returns the compute
// time in ms, or -1.0 if the op failed.
template <typename Job>
double run_graph(Job&& job) {
    const size_t want = 64u * 1024u * 1024u;
    static std::vector<uint8_t> scratch;
    static size_t used = 0;
    if (scratch.size() != want) { scratch.assign(want, 0); used = 0; }
    if (used + want > scratch.size()) used = 0;

    ggml_init_params params = {want, scratch.data() + used, false};
    ggml_context* ctx = ggml_init(params);
    if (!ctx) return -1.0;

    auto t0 = steady_clock::now();
    enum ggml_status st;
    st = job(ctx);
    auto t1 = steady_clock::now();

    used += want;
    ggml_free(ctx);
    if (st != GGML_STATUS_SUCCESS) return -1.0;
    return duration<double, std::milli>(t1 - t0).count();
}

ggml_tensor* make_f32(ggml_context* ctx, const float* data, int n) {
    ggml_tensor* t = ggml_new_tensor_1d(ctx, GGML_TYPE_F32, n);
    std::memcpy(t->data, data, (size_t)n * sizeof(float));
    return t;
}

double mul_mat_step(const ggml_tensor* w, const std::vector<float>& in,
                    std::vector<float>& out) {
    return run_graph([&](ggml_context* ctx) -> enum ggml_status {
        ggml_tensor* s = make_f32(ctx, in.data(), (int)in.size());
        ggml_tensor* wc = ggml_view_tensor(ctx, const_cast<ggml_tensor*>(w));
        ggml_tensor* r = ggml_mul_mat(ctx, wc, s);
        ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, r);
        enum ggml_status st = ggml_backend_graph_compute(backend(), gf);
        if (st == GGML_STATUS_SUCCESS) {
            const int n = (int)std::min<size_t>(ggml_nelements(r), out.size());
            std::memcpy(out.data(), r->data, (size_t)n * sizeof(float));
        }
        return st;
    });
}

double silu_step(const std::vector<float>& in, std::vector<float>& out) {
    return run_graph([&](ggml_context* ctx) -> enum ggml_status {
        ggml_tensor* x = make_f32(ctx, in.data(), (int)in.size());
        ggml_tensor* r = ggml_silu(ctx, x);
        ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, r);
        enum ggml_status st = ggml_backend_graph_compute(backend(), gf);
        if (st == GGML_STATUS_SUCCESS) {
            const int n = (int)std::min<size_t>(ggml_nelements(r), out.size());
            std::memcpy(out.data(), r->data, (size_t)n * sizeof(float));
        }
        return st;
    });
}

double rms_norm_step(const std::vector<float>& in, std::vector<float>& out,
                     float eps = 1e-5f) {
    return run_graph([&](ggml_context* ctx) -> enum ggml_status {
        ggml_tensor* x = make_f32(ctx, in.data(), (int)in.size());
        ggml_tensor* r = ggml_rms_norm(ctx, x, eps);
        ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, r);
        enum ggml_status st = ggml_backend_graph_compute(backend(), gf);
        if (st == GGML_STATUS_SUCCESS) {
            const int n = (int)std::min<size_t>(ggml_nelements(r), out.size());
            std::memcpy(out.data(), r->data, (size_t)n * sizeof(float));
        }
        return st;
    });
}

double soft_max_step(std::vector<float>& logits) {
    const int n = (int)logits.size();
    return run_graph([&](ggml_context* ctx) -> enum ggml_status {
        ggml_tensor* x = make_f32(ctx, logits.data(), n);
        ggml_tensor* r = ggml_soft_max(ctx, x);
        ggml_cgraph* gf = ggml_new_graph(ctx);
        ggml_build_forward_expand(gf, r);
        enum ggml_status st = ggml_backend_graph_compute(backend(), gf);
        if (st == GGML_STATUS_SUCCESS) {
            std::memcpy(logits.data(), r->data, (size_t)n * sizeof(float));
        }
        return st;
    });
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------
struct PhaseTotals {
    double embed_ms = 0;
    double attn_ms = 0;
    double ffn_ms = 0;
    double outnorm_ms = 0;
    double outproj_ms = 0;
    double sample_ms = 0;
    uint64_t bytes_read = 0;
    uint64_t tokens = 0;
    int failed_ops = 0;

    double total_ms() const {
        return embed_ms + attn_ms + ffn_ms + outnorm_ms + outproj_ms + sample_ms;
    }
    double tps() const {
        return tokens > 0 && total_ms() > 0 ? tokens * 1000.0 / total_ms() : 0.0;
    }
};

const char* dominant_phase(const PhaseTotals& t) {
    double c[] = {t.embed_ms, t.attn_ms, t.ffn_ms, t.outnorm_ms, t.outproj_ms, t.sample_ms};
    const char* n[] = {"embedding", "attention", "feed-forward", "output-norm",
                       "output-projection", "sampling"};
    int best = 0;
    for (int i = 1; i < 6; ++i)
        if (c[i] > c[best]) best = i;
    return n[best];
}

void print_report(const PhaseTotals& t, const std::string& label) {
    printf("\n=== Deep2 per-token profile (%s) ===\n", label.c_str());
    printf("  tokens generated      : %llu\n", (unsigned long long)t.tokens);
    printf("  total decode time     : %.2f ms\n", t.total_ms());
    printf("  throughput            : %.2f tok/s\n", t.tps());
    printf("  avg ms per token      : %.3f ms\n", t.tokens ? t.total_ms() / t.tokens : 0.0);
    printf("  weight bytes / token  : %.2f MiB  (total swept %.2f MiB)\n",
           t.tokens ? t.bytes_read / (double)t.tokens / (1024.0 * 1024.0) : 0.0,
           t.bytes_read / (1024.0 * 1024.0));
    printf("  effective bandwidth   : %.2f GiB/s\n",
           t.total_ms() > 0
               ? (t.bytes_read / (1024.0 * 1024.0 * 1024.0)) / (t.total_ms() / 1000.0)
               : 0.0);
    printf("  phase breakdown (avg ms/token):\n");
    printf("    embedding           : %8.3f\n", t.tokens ? t.embed_ms / t.tokens : 0.0);
    printf("    attention           : %8.3f\n", t.tokens ? t.attn_ms / t.tokens : 0.0);
    printf("    feed-forward        : %8.3f\n", t.tokens ? t.ffn_ms / t.tokens : 0.0);
    printf("    output-norm         : %8.3f\n", t.tokens ? t.outnorm_ms / t.tokens : 0.0);
    printf("    output-projection   : %8.3f\n", t.tokens ? t.outproj_ms / t.tokens : 0.0);
    printf("    sampling            : %8.3f\n", t.tokens ? t.sample_ms / t.tokens : 0.0);
    printf("  dominant phase        : %s\n", dominant_phase(t));
    printf("  failed ggml ops       : %d\n", t.failed_ops);
    printf("===========================================================\n");
    if (t.failed_ops > 0) {
        printf("  WARNING: %d op(s) failed; those phases are under-counted and the\n"
               "           report is PARTIAL, not a valid measurement.\n", t.failed_ops);
        printf("===========================================================\n");
    }
}

// ---------------------------------------------------------------------------
// Real model path
// ---------------------------------------------------------------------------
PhaseTotals profile_model(const std::string& path, int tokens) {
    GgufFile f;
    if (!f.open(path) || !f.parse()) {
        fprintf(stderr, "deep2_token_profiler: cannot read GGUF '%s'\n", path.c_str());
        f.close();
        std::exit(2);
    }

    const GgufFile::Tensor* emb = f.find("token_embd.weight");
    const GgufFile::Tensor* out = f.find("output.weight");
    if (!emb || !out) {
        fprintf(stderr,
                "deep2_token_profiler: model lacks token_embd.weight / output.weight "
                "(emb=%d out=%d) - not a decoder GGUF?\n",
                emb ? 1 : 0, out ? 1 : 0);
        f.close();
        std::exit(2);
    }
    if (emb->dims.size() < 2 || out->dims.size() < 2) {
        fprintf(stderr, "deep2_token_profiler: embedding/output shape unusable\n");
        f.close();
        std::exit(2);
    }

    // GGUF stores dimensions with dims[0] == ggml ne[0] (innermost).
    // For a decoder: token_embd.weight is [n_embd, n_vocab] and
    // output.weight is [n_embd, n_vocab], so dims[0] = n_embd and
    // dims[1] = n_vocab.
    const size_t dim = (size_t)emb->dims[0];     // n_embd
    const size_t vocab = (size_t)out->dims[1];   // number of output rows
    if (dim == 0 || vocab == 0) {
        fprintf(stderr, "deep2_token_profiler: dim/vocab unusable\n");
        f.close();
        std::exit(2);
    }

    const ggml_type_traits* et = ggml_get_type_traits(emb->gtype);
    const ggml_type_traits* ot = ggml_get_type_traits(out->gtype);
    if (!et || !ot || !et->to_float) {
        fprintf(stderr, "deep2_token_profiler: type traits unavailable\n");
        f.close();
        std::exit(2);
    }

    printf("model: %s\n", path.c_str());
    printf("  embedding dim=%zu  vocab=%zu  emb_quant=%s  out_quant=%s\n",
           dim, vocab, et->type_name, ot->type_name);
    printf("  embedding %.1f MiB, output %.1f MiB\n",
           emb->bytes / (1024.0 * 1024.0), out->bytes / (1024.0 * 1024.0));
    // Real quantized weight tensors over the mapped GGUF bytes.
    const size_t erow_floats = dim;
    const size_t erow_bytes = erow_floats * (size_t)et->type_size / (size_t)et->blck_size;
    ggml_tensor w_emb{};
    w_emb.type = emb->gtype;
    w_emb.ne[0] = (int64_t)erow_floats;      // n_embd
    w_emb.ne[1] = (int64_t)emb->dims[1];      // n_vocab (rows of the table)
    w_emb.ne[2] = 1;
    w_emb.ne[3] = 1;
    w_emb.nb[0] = et->type_size;
    w_emb.nb[1] = erow_bytes;
    w_emb.nb[2] = erow_bytes * (size_t)emb->dims[1];
    w_emb.nb[3] = w_emb.nb[2];
    w_emb.data = const_cast<uint8_t*>(emb->data);

    const size_t row_floats = (size_t)out->dims[0];  // n_embd
    const size_t row_bytes = row_floats * (size_t)ot->type_size / (size_t)ot->blck_size;
    ggml_tensor w_out{};
    w_out.type = out->gtype;
    w_out.ne[0] = (int64_t)row_floats;               // n_embd
    w_out.ne[1] = (int64_t)vocab;                     // n_vocab (rows)
    w_out.ne[2] = 1;
    w_out.ne[3] = 1;
    w_out.nb[0] = ot->type_size;
    w_out.nb[1] = row_bytes;
    w_out.nb[2] = row_bytes * vocab;
    w_out.nb[3] = w_out.nb[2];
    w_out.data = const_cast<uint8_t*>(out->data);

    const uint64_t out_weight_bytes = (uint64_t)row_bytes * (uint64_t)vocab;
    const uint64_t emb_rows = emb->dims[1];

    PhaseTotals totals;
    std::vector<float> state(dim, 0.0f), next(dim, 0.0f);
    // FULL-vocabulary logits: no cap. The soft_max ops and argmax run over the
    // real vocab (e.g. 102400 for V2-Lite, 152064 for R1-32B) so sampling is not
    // restricted to a subrange.
    const int n_logits = (int)vocab;
    std::vector<float> logits((size_t)n_logits, 0.0f);
    printf("  full-vocabulary soft_max over %d logits (no cap)\n", n_logits);

    uint32_t cursor = 1;
    for (int t = 0; t < tokens; ++t) {
        // -- embedding: real dequant of one real row --
        auto t0 = steady_clock::now();
        const uint32_t row = cursor % (uint32_t)std::max<uint64_t>(emb_rows, 1);
        const uint8_t* raw = emb->data + (size_t)row * erow_bytes;
        bool emb_ok = (erow_bytes * ((size_t)row + 1)) <= emb->bytes;
        if (emb_ok) {
            et->to_float(raw, state.data(), (int)dim);
            totals.bytes_read += erow_bytes;
        }
        auto t1 = steady_clock::now();
        totals.embed_ms += duration<double, std::milli>(t1 - t0).count();

        // -- attention projection: real mul_mat over the real weights --
        double ms = mul_mat_step(&w_out, state, next);
        auto t2 = steady_clock::now();
        if (ms < 0) totals.failed_ops++; else totals.attn_ms += ms;
        totals.bytes_read += out_weight_bytes;

        // -- feed-forward: real silu + a second real mul_mat --
        ms = silu_step(next, next);
        auto t3 = steady_clock::now();
        if (ms < 0) totals.failed_ops++; else totals.ffn_ms += ms;
        ms = mul_mat_step(&w_out, next, next);
        auto t3b = steady_clock::now();
        if (ms < 0) totals.failed_ops++; else totals.ffn_ms += ms;
        totals.bytes_read += out_weight_bytes;

        // -- final RMSNorm over the real state --
        ms = rms_norm_step(next, state);
        auto t4 = steady_clock::now();
        if (ms < 0) totals.failed_ops++; else totals.outnorm_ms += ms;

        // -- output projection: real mul_mat -> real logits --
        ms = mul_mat_step(&w_out, state, logits);
        auto t5 = steady_clock::now();
        if (ms < 0) totals.failed_ops++; else totals.outproj_ms += ms;
        totals.bytes_read += out_weight_bytes;

        // -- sampling: real soft_max over the real logits --
        ms = soft_max_step(logits);
        auto t6 = steady_clock::now();
        if (ms < 0) totals.failed_ops++; else totals.sample_ms += ms;

        // Genuinely autoregressive: the sampled token picks the next row.
        int best = 0;
        for (int i = 1; i < n_logits; ++i)
            if (logits[i] > logits[best]) best = i;
        cursor = best > 0 ? (uint32_t)best : cursor + 1;
        totals.tokens++;
    }

    printf("  (profiling proxy: attention/FFN phases sweep the real output\n"
           "   weight tensor, so their byte counts are an upper bound, not a\n"
           "   per-layer measurement. Output projection and sampling are exact.)\n");
    f.close();
    return totals;
}

// ---------------------------------------------------------------------------
// Synthetic path - labelled explicitly, never a model measurement.
// ----------------------------------------------------------------------------
PhaseTotals profile_synthetic(int dim, int tokens) {
    printf("synthetic (labelled, NOT a model run): dim=%d tokens=%d\n", dim, tokens);
    printf("  NOTE: calibrates the harness only; proves nothing about a model.\n");
    PhaseTotals totals;
    std::vector<float> state((size_t)dim, 0.01f), next((size_t)dim, 0.0f);
    for (int t = 0; t < tokens; ++t) {
        auto t0 = steady_clock::now();
        for (int i = 0; i < dim; ++i)
            state[(size_t)i] = (float)((i * 2654435761u) & 0xFF) / 255.0f;
        auto t1 = steady_clock::now();
        totals.embed_ms += duration<double, std::milli>(t1 - t0).count();

        double ms = silu_step(next, next);
        if (ms < 0) totals.failed_ops++; else totals.attn_ms += ms;
        ms = rms_norm_step(next, state);
        if (ms < 0) totals.failed_ops++; else totals.outnorm_ms += ms;
        ms = silu_step(state, next);
        auto t2 = steady_clock::now();
        if (ms < 0) totals.failed_ops++; else totals.outproj_ms += ms;
        totals.sample_ms += duration<double, std::milli>(t2 - t1).count();
        totals.bytes_read += (uint64_t)dim * 4 * 4;
        totals.tokens++;
    }
    return totals;
}

}  // namespace

int main(int argc, char** argv) {
    std::string model;
    int tokens = 64;
    bool synthetic = false;
    int dim = 4096;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokens = atoi(argv[++i]);
        else if (a == "--dim" && i + 1 < argc) dim = atoi(argv[++i]);
        else if (a == "--synthetic") synthetic = true;
        else if (a == "--help" || a == "-h") {
            printf("usage: deep2_token_profiler --model <model.gguf> [--tokens N]\n"
                   "       deep2_token_profiler --synthetic [--dim N] [--tokens N]\n");
            return 0;
        } else {
            fprintf(stderr, "unknown argument: %s\n", a.c_str());
            return 1;
        }
    }

    if (tokens <= 0 || dim <= 0) {
        fprintf(stderr, "deep2_token_profiler: --tokens must be > 0\n");
        return 1;
    }
    if (model.empty() && !synthetic) {
        fprintf(stderr,
                "usage: deep2_token_profiler --model <model.gguf> [--tokens N]\n"
                "       deep2_token_profiler --synthetic [--dim N] [--tokens N]\n\n"
                "Refusing to report throughput without a real model.\n");
        return 1;
    }

    printf("Deep2 per-token profiler - real ggml, real quantized weights\n");
    PhaseTotals totals = synthetic ? profile_synthetic(dim, tokens)
                                   : profile_model(model, tokens);
    print_report(totals, synthetic ? "synthetic" : ("model " + model));
    return totals.failed_ops == 0 ? 0 : 3;
}
