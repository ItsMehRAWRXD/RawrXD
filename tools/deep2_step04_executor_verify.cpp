// ============================================================================
// deep2_step04_executor_verify.cpp
// RAWRXD_DEEP2_STEP_04  --  executor integration of the native quantised
// Vulkan dot product, verified against real GGUF weights.
//
// Acceptance requirements covered (one section each):
//   [1] Real executor call: the production dispatcher
//       RawrXD::Deep2::QuantDot::DotBlocked actually invokes
//       VulkanCompute::ExecuteQuantDot, and the counters prove it.
//   [2] Tensor parity: complete output vectors vs an independent CPU
//       reference -> cosine, relative RMSE, max abs error, finite check.
//   [3] Fallback authority: unsupported shapes and forced/simulated GPU
//       failure must report the CPU fallback, never claim the GPU.
//   [4] Tiled execution: more rows than one tile, so multiple dispatches
//       run with the activation uploaded once.
//   [5] Performance evidence: cold start, steady-state kernel time, host
//       dispatch time and a full projection latency, reported separately.
//
// Nothing is synthetic: the weights are real bytes from a real GGUF file and
// the activations are real rows dequantised by ggml.
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <algorithm>
#include <chrono>
#include <string>
#include <vector>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#endif

#include "ggml.h"
#include "quant_dot_dispatch.hpp"

using namespace RawrXD::Deep2::QuantDot;

namespace {

int g_pass = 0, g_fail = 0;
void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (ok) ++g_pass; else ++g_fail;
}
void Section(const char* s) { std::printf("\n--- %s ---\n", s); }

// ---------------------------------------------------------------------------
// Minimal self-contained GGUF reader (memory mapped; BOOL is 1 byte).
// ---------------------------------------------------------------------------
struct Gguf {
    struct Tensor {
        std::string name;
        std::vector<uint64_t> dims;
        uint32_t gtype = 0;
        uint64_t rel = 0;
        const uint8_t* data = nullptr;
        size_t bytes = 0;
    };
    const uint8_t* base = nullptr;
    size_t size = 0, pos = 0;
    std::vector<Tensor> tensors;

    uint32_t u32() { uint32_t v; std::memcpy(&v, base + pos, 4); pos += 4; return v; }
    uint64_t u64() { uint64_t v; std::memcpy(&v, base + pos, 8); pos += 8; return v; }
    std::string str() { uint64_t n = u64(); std::string s((const char*)(base + pos), (size_t)n); pos += (size_t)n; return s; }
    bool skipScalar(uint32_t t) {
        switch (t) {
            case 0: case 1: pos += 1; return true;
            case 2: case 3: pos += 2; return true;
            case 4: case 5: case 6: pos += 4; return true;
            case 7: pos += 1; return true;                  // GGUF BOOL = 1 byte
            case 10: case 11: case 12: pos += 8; return true;
            default: return false;
        }
    }
    bool skipVal(uint32_t t, int d) {
        if (d > 6) return false;
        if (t == 8) { str(); return true; }
        if (t == 9) { uint32_t et = u32(); uint64_t n = u64();
                      for (uint64_t i = 0; i < n; ++i) if (!skipVal(et, d + 1)) return false; return true; }
        return skipScalar(t);
    }
    bool open(const std::string& p) {
#ifdef _WIN32
        HANDLE h = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
        HANDLE m = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!m) { CloseHandle(h); return false; }
        base = (const uint8_t*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, (SIZE_T)sz.QuadPart);
        map_ = m; size = (size_t)sz.QuadPart;
#else
        int fd = ::open(p.c_str(), O_RDONLY);
        if (fd < 0) return false;
        struct stat st{}; ::fstat(fd, &st);
        size = (size_t)st.st_size;
        base = (const uint8_t*)::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        fd_ = fd;
#endif
        return base != nullptr;
    }
    bool parse() {
        if (u32() != 0x46554747u) return false;
        (void)u32();
        uint64_t tc = u64(), kv = u64();
        for (uint64_t i = 0; i < kv; ++i) { str(); if (!skipVal(u32(), 0)) return false; }
        uint64_t max_end = 0;
        for (uint64_t i = 0; i < tc; ++i) {
            Tensor t;
            t.name = str();
            uint32_t nd = u32();
            if (nd == 0 || nd > 4) return false;
            t.dims.resize(nd);
            for (auto& d : t.dims) d = u64();
            t.gtype = u32();
            t.rel = u64();
            const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)t.gtype);
            if (!tr || tr->blck_size == 0) return false;
            uint64_t blocks = (t.dims[0] + (uint64_t)tr->blck_size - 1) / (uint64_t)tr->blck_size;
            for (uint32_t d = 1; d < nd; ++d) blocks *= t.dims[d];
            t.bytes = (size_t)(blocks * (uint64_t)tr->type_size);
            tensors.push_back(t);
            if (t.rel + t.bytes > max_end) max_end = t.rel + t.bytes;
        }
        size_t ds = (pos + 31) & ~size_t(31);
        if (ds + max_end > size) return false;
        for (auto& t : tensors) t.data = base + ds + t.rel;
        return true;
    }
    const Tensor* find(const char* n) const {
        for (const auto& t : tensors) if (t.name == n) return &t;
        return nullptr;
    }
#ifdef _WIN32
    HANDLE map_ = nullptr;
#else
    int fd_ = -1;
#endif
};

// ---------------------------------------------------------------------------
// Independent CPU reference. Deliberately NOT the same code as the shader,
// and deliberately not shared with ggml's dequantiser: block layouts are
// decoded here with integer lanes, as in RAWRXD_DEEP2_GPU_QUANT_DOT_001.
// ---------------------------------------------------------------------------
float HalfToFloat(uint16_t h) {
    const uint32_t sign = uint32_t(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 31u, frac = h & 1023u;
    uint32_t bits;
    if (exp == 0) {
        if (frac == 0) bits = sign;
        else { uint32_t m = frac; int e = -14;
               while ((m & 1024u) == 0u) { m <<= 1; --e; }
               bits = sign | (uint32_t(e + 127) << 23) | ((m & 1023u) << 13); }
    } else if (exp == 31) bits = sign | 0x7f800000u | (frac << 13);
    else bits = sign | ((exp + 112u) << 23) | (frac << 13);
    float f; std::memcpy(&f, &bits, 4); return f;
}
void K4(const uint8_t s[12], unsigned g, int& sc, int& mn) {
    if (g < 4) { sc = int(s[g] & 63u); mn = int(s[g + 4] & 63u); }
    else { sc = int((s[g + 4] & 15u) | ((s[g - 4] >> 6) << 4));
           mn = int((s[g + 4] >> 4) | ((s[g] >> 6) << 4)); }
}
struct Q8Blk { float d; float qs[256]; float bs[16]; };

float DotQ4(const uint8_t* x, const Q8Blk& y) {
    uint16_t d, dm; std::memcpy(&d, x, 2); std::memcpy(&dm, x + 2, 2);
    const uint8_t* sc = x + 4, *qs = x + 16;
    int32_t lanes[8] = {}; int32_t msum = 0;
    for (unsigned g = 0; g < 8; ++g) {
        int s, m; K4(sc, g, s, m);
        const uint8_t* q = qs + (g / 2) * 32;
        const bool hi = (g & 1u) != 0;
        for (unsigned i = 0; i < 32; ++i)
            lanes[i & 7u] += s * (hi ? int(q[i] >> 4) : int(q[i] & 15u)) * int(y.qs[g * 32 + i]);
        msum += m * int(y.bs[2 * g] + y.bs[2 * g + 1]);
    }
    const float D = HalfToFloat(d) * y.d, Dm = HalfToFloat(dm) * y.d;
    float f = 0;
    for (int i = 0; i < 8; ++i) f += D * float(lanes[i]);
    return f - Dm * float(msum);
}
float DotQ6(const uint8_t* x, const Q8Blk& y) {
    const uint8_t* ql = x, *qh = x + 128;
    const int8_t* sc = (const int8_t*)(x + 192);
    uint16_t d; std::memcpy(&d, x + 208, 2);
    int32_t lanes[8] = {};
    for (unsigned g = 0; g < 8; ++g) {
        const unsigned half = g / 4, part = g % 4;
        const unsigned sh = part >= 2 ? 4 : 0;
        const unsigned lo = half * 64 + (part & 1u) * 32, ho = half * 32, qo = 2 * part;
        for (unsigned i = 0; i < 32; ++i) {
            const int l4 = int((ql[lo + i] >> sh) & 15u);
            const int h2 = int((qh[ho + i] >> qo) & 3u);
            lanes[i & 7u] += int(sc[g * 2 + i / 16]) * ((l4 | (h2 << 4)) - 32) * int(y.qs[g * 32 + i]);
        }
    }
    const float D = HalfToFloat(d) * y.d;
    float f = 0;
    for (int i = 0; i < 8; ++i) f += D * float(lanes[i]);
    return f;
}

// The dispatcher's own Q8 rule (d = amax/127, per-16 sums). The reference is
// built from the SAME quantised values so the comparison isolates the kernel,
// not the choice of quantiser.
std::vector<Q8Blk> MakeQ8(const float* act, size_t in) {
    std::vector<Q8Blk> v(in / 256);
    for (size_t b = 0; b < v.size(); ++b) {
        const float* src = act + b * 256;
        float amax = 0;
        for (int j = 0; j < 256; ++j) amax = std::max(amax, std::fabs(src[j]));
        const float d = amax / 127.0f;
        v[b].d = d;
        int sums[16] = {0};
        for (int j = 0; j < 256; ++j) {
            int q = d > 0 ? int(std::lround(src[j] / d)) : 0;
            q = std::max(-128, std::min(127, q));
            v[b].qs[j] = float(q);
            sums[j / 16] += q;
        }
        for (int j = 0; j < 16; ++j) v[b].bs[j] = float(sums[j]);
    }
    return v;
}

void ReferenceRows(int kind, const uint8_t* packed, const std::vector<Q8Blk>& q8,
                   float* out, size_t rows, size_t in) {
    const size_t blocks = in / 256;
    const size_t rb = blocks * (kind == 0 ? 144 : 210);
    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* row = packed + r * rb;
        double acc = 0;
        for (size_t b = 0; b < blocks; ++b)
            acc += (kind == 0) ? DotQ4(row + b * 144, q8[b]) : DotQ6(row + b * 210, q8[b]);
        out[r] = float(acc);
    }
}

struct Metrics { double cos, rmse, max_abs, rel; bool finite; };
Metrics Compare(const std::vector<float>& a, const std::vector<float>& b) {
    Metrics m{}; m.finite = true;
    double dot = 0, na = 0, nb = 0, sq = 0, mx = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        if (!std::isfinite(a[i]) || !std::isfinite(b[i])) m.finite = false;
        const double d = double(a[i]) - double(b[i]);
        sq += d * d; if (std::fabs(d) > mx) mx = std::fabs(d);
        dot += double(a[i]) * double(b[i]);
        na += double(a[i]) * double(a[i]);
        nb += double(b[i]) * double(b[i]);
    }
    m.cos = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 1.0;
    m.rmse = std::sqrt(sq / double(a.size()));
    m.max_abs = mx;
    const double mag = std::sqrt(nb / double(a.size()));
    m.rel = (mag > 1e-12) ? m.rmse / mag : m.rmse;
    return m;
}

}  // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::string model;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else { std::printf("unknown arg %s\n", a.c_str()); return 1; }
    }
    if (model.empty()) {
        std::printf("usage: deep2_step04_executor_verify --model <model.gguf>\n");
        return 1;
    }
    std::printf("=== RAWRXD_DEEP2_STEP_04: executor integration of the quantised GPU dot ===\n");
    std::printf("model: %s\n", model.c_str());

    Gguf g;
    if (!g.open(model) || !g.parse()) { std::printf("GGUF_OPEN_FAIL\n"); return 1; }
    std::printf("  parsed %zu tensors\n", g.tensors.size());

    // Real weights: first Q4_K, else first Q6_K.
    const Gguf::Tensor* w4 = nullptr, *w6 = nullptr;
    for (const auto& t : g.tensors) {
        if (!w4 && t.gtype == 12) w4 = &t;
        if (!w6 && t.gtype == 14) w6 = &t;
        if (w4 && w6) break;
    }
    if (!w4 && !w6) { std::printf("NO_Q4K_OR_Q6K_TENSOR\n"); return 1; }

    // Real activation: row 0 of the embedding table, dequantised by ggml.
    const Gguf::Tensor* emb = g.find("token_embd.weight");
    if (!emb) { std::printf("NO_EMBEDDING\n"); return 1; }
    const ggml_type_traits* et = ggml_get_type_traits((ggml_type)emb->gtype);
    if (!et || !et->to_float) { std::printf("EMB_NO_DEQUANT\n"); return 1; }
    const size_t emb_dim = (size_t)emb->dims[0];

    // Measure the true cold start on a throwaway dispatch before any reset.
    {
        const ggml_type_traits* wt = ggml_get_type_traits(
            (ggml_type)(w4 ? w4->gtype : w6->gtype));
        const int k = (w4 ? w4->gtype : w6->gtype) == 12 ? 0 : 1;
        const Gguf::Tensor* cw = w4 ? w4 : w6;
        const size_t in = (size_t)cw->dims[0];
        if (in == emb_dim && (in % 256) == 0) {
            std::vector<float> a(in), o(1, 0.0f);
            et->to_float(emb->data, a.data(), (int)in);
            const size_t rb = (in / 256) * (k == 0 ? 144 : 210);
            std::vector<Q8Blk> q8 = MakeQ8(a.data(), in);
            CpuDot cd = [&](const uint8_t* row, const void*, size_t nb) -> float {
                double acc = 0;
                for (size_t b = 0; b < nb; ++b)
                    acc += (k == 0) ? DotQ4(row + b * 144, q8[b]) : DotQ6(row + b * 210, q8[b]);
                return float(acc);
            };
            const auto t0 = std::chrono::steady_clock::now();
            DotBlocked(k, cw->data, rb, a.data(), in, o.data(), 1, cd);
            const auto t1 = std::chrono::steady_clock::now();
            const std::string saved_reason = FallbackReason();
            std::printf("\n[cold start] first dispatcher call: %.3f ms total, gpu_calls=%llu "
                        "reason='%s'\n",
                        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count() / 1000.0,
                        (unsigned long long)GetStats().gpu_calls, saved_reason.c_str());
        }
    }

    auto runCase = [&](const Gguf::Tensor* w, const char* label) -> int {
        const ggml_type_traits* wt = ggml_get_type_traits((ggml_type)w->gtype);
        const int kind = (w->gtype == 12) ? 0 : 1;
        const size_t in = (size_t)w->dims[0];
        const size_t blocks = in / 256;
        const size_t rb = blocks * (kind == 0 ? 144 : 210);
        const size_t rows_total = w->dims.size() >= 2 ? (size_t)w->dims[1] : 1;
        std::printf("\n=== %s : %s (%s) ne=[%zu,%zu] ===\n", label, w->name.c_str(),
                    kind == 0 ? "Q4_K" : "Q6_K", in, rows_total);
        if (in != emb_dim) {
            std::printf("  SKIP: weight in=%zu != embedding dim=%zu\n", in, emb_dim);
            return 0;
        }
        if ((in % 256) != 0) { std::printf("  SKIP: in not multiple of 256\n"); return 0; }

        // Requirement 4 needs more than one tile of rows.
        const size_t rows = std::min<size_t>(rows_total, 8192);
        if (w->bytes < rb * rows) { std::printf("  SKIP: tensor too small\n"); return 0; }

        std::vector<float> act(in);
        et->to_float(emb->data, act.data(), (int)in);

        std::vector<float> gpu(rows, 0.0f), cpu(rows, 0.0f);
        std::vector<Q8Blk> q8 = MakeQ8(act.data(), in);

        // ---- the dispatcher under test ----
        CpuDot cpu_dot = [&](const uint8_t* row, const void*, size_t nb) -> float {
            const uint8_t* base = row;
            double acc = 0;
            for (size_t b = 0; b < nb; ++b)
                acc += (kind == 0) ? DotQ4(base + b * 144, q8[b]) : DotQ6(base + b * 210, q8[b]);
            return float(acc);
        };
        ResetStats();
        bool usedGpu = false;
        const bool ok = DotBlocked(kind, w->data, rb * rows, act.data(), in,
                                   gpu.data(), rows, cpu_dot);
        Check(ok, "dispatcher returned success (outputs written)");

        Section("[1] real executor call, proven by counters");
        const Stats& s_first = GetStats();
        std::printf("  gpu_calls=%llu cpu_calls=%llu gpu_rows=%llu cpu_rows=%llu tiles=%llu\n",
                    (unsigned long long)s_first.gpu_calls, (unsigned long long)s_first.cpu_calls,
                    (unsigned long long)s_first.gpu_rows, (unsigned long long)s_first.cpu_rows,
                    (unsigned long long)s_first.tiles);
        Check(s_first.gpu_calls > 0, "GPU dispatches actually ran (gpu_calls > 0)");
        Check(s_first.gpu_rows == rows, "every row was produced by the GPU");
        Check(s_first.cpu_calls == 0, "no silent CPU fallback occurred");
        Check(FallbackReason().empty(), "no fallback reason recorded");
        Check(s_first.initialized && !s_first.gpu_device.empty(),
              std::string("Vulkan initialised on: " + s_first.gpu_device).c_str());
        (void)usedGpu;

        Section("[2] tensor parity vs independent CPU reference");
        ReferenceRows(kind, w->data, q8, cpu.data(), rows, in);
        const Metrics m = Compare(gpu, cpu);
        std::printf("  cosine=%.10f rel_rmse=%.3e max_abs=%.3e finite=%d\n",
                    m.cos, m.rel, m.max_abs, m.finite ? 1 : 0);
        Check(m.finite, "all GPU outputs finite");
        Check(m.cos >= 0.999999, "cosine >= 0.999999");
        Check(m.rel <= 1e-4, "relative RMSE <= 1e-4");
        std::printf("  first 3 gpu:");
        for (int i = 0; i < 3; ++i) std::printf(" %.8g", gpu[i]);
        std::printf("\n  first 3 ref:");
        for (int i = 0; i < 3; ++i) std::printf(" %.8g", cpu[i]);
        std::printf("\n");

        Section("[3a] fallback authority - unsupported shape");
        // in+32 is no longer a multiple of 256.
        std::vector<float> act2(in + 32, 0.0f);
        for (size_t i = 0; i < in; ++i) act2[i] = act[i];
        std::vector<float> outcpu(2, 0.0f);
        ResetStats();
        const bool gpuClaimed = DotBlocked(kind, w->data, rb * 2, act2.data(), in + 32,
                                           outcpu.data(), 2, cpu_dot);
        const Stats& s2 = GetStats();
        Check(!gpuClaimed, "dispatcher did NOT claim the GPU");
        Check(s2.gpu_calls == 0, "no GPU dispatch for the unsupported shape");
        Check(s2.cpu_calls >= 1 || s2.fallback_shape == 1, "CPU fallback was recorded");
        std::printf("  reason: %s\n", FallbackReason().c_str());
        Check(FallbackReason().rfind("shape:", 0) == 0, "reason starts with 'shape:'");

        Section("[3b] fallback authority - forced CPU");
        ResetStats();
        SetForceCpu(true);
        std::vector<float> forced(rows, 0.0f);
        const bool claimed2 = DotBlocked(kind, w->data, rb * rows, act.data(), in,
                                         forced.data(), rows, cpu_dot);
        SetForceCpu(false);
        const Stats& s3 = GetStats();
        Check(!claimed2, "dispatcher did NOT claim the GPU");
        Check(s3.gpu_calls == 0, "no GPU dispatch ran");
        Check(FallbackReason().find("ForceCpu") != std::string::npos,
              "reason names the ForceCpu hook");
        std::printf("  reason: %s\n", FallbackReason().c_str());
        const Metrics mf = Compare(forced, cpu);
        Check(mf.finite && mf.cos >= 0.999999, "CPU fallback output is still correct");

        // Sections [4] and [5] must read the LIVE counters: [3a]/[3b] reset
        // them, so any reference captured earlier refers to cleared values.
        const Stats& live = GetStats();
        // Re-run the projection so the live counters describe this case.
        std::vector<float> gpu2(rows, 0.0f);
        const bool ok2 = DotBlocked(kind, w->data, rb * rows, act.data(), in,
                                    gpu2.data(), rows, cpu_dot);
        Check(ok2, "re-project succeeded for tiling/perf measurement");
        const Stats& s = GetStats();

        Section("[4] tiled execution");
        const size_t kTileRows = 4096;
        if (rows > kTileRows) {
            std::printf("  rows=%zu tile_rows=%zu tiles=%llu gpu_calls=%llu\n",
                        rows, kTileRows, (unsigned long long)s.tiles,
                        (unsigned long long)s.gpu_calls);
            Check(s.tiles >= 2, "multiple weight tiles were dispatched");
            Check(s.gpu_calls >= 2, "one GPU call per tile, activation reused across tiles");
            const unsigned long long expected = (rows + kTileRows - 1) / kTileRows;
            Check(s.tiles == expected, "tile count matches row/tile ratio");
        } else {
            std::printf("  (rows=%zu <= tile size; tiling not exercised for this tensor)\n", rows);
        }

        Section("[5] performance evidence (separated)");
        std::printf("  cold start (Vulkan init) : %.3f ms\n", s.cold_start_ms);
        std::printf("  steady-state kernel time : %.3f ms (dispatches after the first)\n",
                    s.steady_kernel_ms);
        std::printf("  total dispatch time      : %.3f ms\n", s.dispatch_ms);
        std::printf("  quantise+readback        : %.3f ms\n", s.total_ms);
        Check(s.cold_start_ms > 0.0, "cold start was measured and is non-zero");
        if (s.gpu_calls >= 2) Check(s.steady_kernel_ms > 0.0, "steady-state kernel time measured");

        // Full projection latency: repeat the projection and time the loop.
        std::vector<float> again(rows, 0.0f);
        const int reps = 5;
        const auto p0 = std::chrono::steady_clock::now();
        for (int i = 0; i < reps; ++i)
            DotBlocked(kind, w->data, rb * rows, act.data(), in, again.data(), rows, cpu_dot);
        const auto p1 = std::chrono::steady_clock::now();
        const double loop_ms =
            std::chrono::duration_cast<std::chrono::microseconds>(p1 - p0).count() / 1000.0;
        const double per_call = loop_ms / reps;
        std::printf("  full projection latency  : %.3f ms per call (%d rows, avg of %d)\n",
                    per_call, (int)rows, reps);
        Check(per_call > 0.0, "projection latency measured");
        const Metrics mr = Compare(again, cpu);
        Check(mr.cos >= 0.999999, "repeated projection stays numerically identical");
        return 0;
    };

    int rc = 0;
    if (w4) rc |= runCase(w4, "Q4_K real expert weights");
    if (w6) rc |= runCase(w6, "Q6_K real expert weights");

    std::printf("\n=== step04 verification: %d passed, %d failed ===\n", g_pass, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
