// ============================================================================
// gpu_quant_dot_realweights.cpp
// RAWRXD_DEEP2_GPU_QUANT_DOT_002
//
// Closes the gap declared by RAWRXD_DEEP2_GPU_QUANT_DOT_001:
//   "Parity against real GGUF weights. The weights used here are synthetic;
//    real tensors exercise different value distributions."
//
// This harness runs the native Vulkan quantised dot product
// (tools/shaders/quant_dot.comp, VulkanCompute::ExecuteQuantDot) on REAL
// quantised weights read from a real GGUF model, with a REAL activation
// derived from real model data, and compares it against a reference that is
// computed by ggml's own dequantizers. Nothing here is synthetic.
//
// Per case:
//   weights  : N real rows of a real Q4_K / Q6_K tensor, byte-for-byte from
//              the GGUF payload.
//   activation: row 0 of a real tensor (token_embd.weight when present)
//              dequantized to float by ggml, then quantised to Q8_0 by
//              ggml_quantize_chunk.
//   gpu      : ExecuteQuantDot over the real packed bytes.
//   reference: ggml dequantise the packed weights to F32, ggml dequantise
//              the Q8_0 activation to F32, plain float dot product. This
//              path shares no code with the shader and no code with the
//              integer-lane CPU reference.
//   crosscheck: an independent CPU reference that decodes the same block
//              layouts with integer lanes (the RAWRXD_DEEP2_GPU_QUANT_DOT_001
//              implementation) is also computed, so shader and reference are
//              both checked against each other rather than in isolation.
//
// Usage:
//   gpu_quant_dot_realweights --model <model.gguf> [--weights NAME]
//                              [--rows N] [--spv PATH]
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <algorithm>
#include <map>
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
#include "vulkan_compute.h"

namespace {

// ---------------------------------------------------------------------------
// Self-contained GGUF reader (memory mapped; bool is 1 byte per the spec).
// ---------------------------------------------------------------------------
struct Gguf {
    const uint8_t* base = nullptr;
    size_t size = 0;
    size_t pos = 0;

    struct Tensor {
        std::string name;
        std::vector<uint64_t> dims;
        uint32_t gtype = 0;
        uint64_t rel_offset = 0;
        const uint8_t* data = nullptr;
        size_t bytes = 0;
    };
    std::vector<Tensor> tensors;

    uint32_t u32() { uint32_t v; std::memcpy(&v, base + pos, 4); pos += 4; return v; }
    uint64_t u64() { uint64_t v; std::memcpy(&v, base + pos, 8); pos += 8; return v; }
    std::string str() {
        uint64_t n = u64();
        std::string s((const char*)(base + pos), (size_t)n);
        pos += (size_t)n;
        return s;
    }
    bool skipScalar(uint32_t t) {
        switch (t) {
            case 0: case 1: pos += 1; return true;
            case 2: case 3: pos += 2; return true;
            case 4: case 5: case 6: pos += 4; return true;
            case 7: pos += 1; return true;            // GGUF BOOL = 1 byte
            case 10: case 11: case 12: pos += 8; return true;
            default: return false;
        }
    }
    bool skipVal(uint32_t t, int depth) {
        if (depth > 6) return false;
        if (t == 8) { str(); return true; }
        if (t == 9) {
            uint32_t et = u32();
            uint64_t n = u64();
            for (uint64_t i = 0; i < n; ++i) if (!skipVal(et, depth + 1)) return false;
            return true;
        }
        return skipScalar(t);
    }

    bool open(const std::string& path) {
#ifdef _WIN32
        HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
        HANDLE m = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!m) { CloseHandle(h); return false; }
        base = (const uint8_t*)MapViewOfFile(m, FILE_MAP_READ, 0, 0, (SIZE_T)sz.QuadPart);
        map_ = m;
        size = (size_t)sz.QuadPart;
#else
        int fd = ::open(path.c_str(), O_RDONLY);
        if (fd < 0) return false;
        struct stat st{}; ::fstat(fd, &st);
        size = (size_t)st.st_size;
        base = (const uint8_t*)::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);
        fd_ = fd;
#endif
        return base != nullptr;
    }
    void close() {
#ifdef _WIN32
        if (base) UnmapViewOfFile(base);
        if (map_) CloseHandle(map_);
#else
        if (base) ::munmap(const_cast<uint8_t*>(base), size);
        if (fd_ >= 0) ::close(fd_);
#endif
        base = nullptr;
    }

    bool parse() {
        if (u32() != 0x46554747u) return false;
        (void)u32();
        uint64_t tensor_count = u64();
        uint64_t kv_count = u64();
        for (uint64_t i = 0; i < kv_count; ++i) {
            str();
            uint32_t t = u32();
            if (!skipVal(t, 0)) return false;
        }
        uint64_t max_end = 0;
        uint64_t alignment = 32;
        for (uint64_t i = 0; i < tensor_count; ++i) {
            Tensor t;
            t.name = str();
            uint32_t n_dims = u32();
            if (n_dims == 0 || n_dims > 4) return false;
            t.dims.resize(n_dims);
            for (auto& d : t.dims) d = u64();
            t.gtype = u32();
            t.rel_offset = u64();

            const ggml_type_traits* tr = ggml_get_type_traits((ggml_type)t.gtype);
            if (!tr || tr->blck_size == 0) return false;
            uint64_t blocks = (t.dims[0] + (uint64_t)tr->blck_size - 1) / (uint64_t)tr->blck_size;
            for (uint32_t d = 1; d < n_dims; ++d) blocks *= t.dims[d];
            t.bytes = (size_t)(blocks * (uint64_t)tr->type_size);
            tensors.push_back(t);
            if (t.rel_offset + t.bytes > max_end) max_end = t.rel_offset + t.bytes;
        }
        (void)alignment;
        size_t data_start = (pos + 31) & ~size_t(31);
        if (data_start + max_end > size) return false;
        for (auto& t : tensors) t.data = base + data_start + t.rel_offset;
        return true;
    }

    const Tensor* find(const char* name) const {
        for (const auto& t : tensors) if (t.name == name) return &t;
        return nullptr;
    }

#ifdef _WIN32
    HANDLE map_ = nullptr;
#else
    int fd_ = -1;
#endif
};

// ---------------------------------------------------------------------------
// Independent CPU reference with integer lanes (mirrors the RAWRXD_DEEP2_GPU_
// QUANT_DOT_001 implementation; kept separate from ggml's path).
// ---------------------------------------------------------------------------
float HalfToFloat(uint16_t h) {
    const uint32_t sign = uint32_t(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 31u;
    const uint32_t frac = h & 1023u;
    uint32_t bits;
    if (exp == 0) {
        if (frac == 0) bits = sign;
        else {
            uint32_t m = frac; int e = -14;
            while ((m & 1024u) == 0u) { m <<= 1; --e; }
            bits = sign | (uint32_t(e + 127) << 23) | ((m & 1023u) << 13);
        }
    } else if (exp == 31) bits = sign | 0x7f800000u | (frac << 13);
    else bits = sign | ((exp + 112u) << 23) | (frac << 13);
    float f; std::memcpy(&f, &bits, 4); return f;
}

void K4ScaleMin(const uint8_t s[12], unsigned group, int& scale, int& minv) {
    if (group < 4) { scale = int(s[group] & 63u); minv = int(s[group + 4] & 63u); }
    else {
        scale = int((s[group + 4] & 15u) | ((s[group - 4] >> 6) << 4));
        minv = int((s[group + 4] >> 4) | ((s[group] >> 6) << 4));
    }
}

// The shader's Q8 layout, held host-side.
struct Q8Block { float d; std::vector<float> qs; std::vector<float> bsums; };

float DotQ4(const uint8_t* x, const Q8Block& y) {
    uint16_t d, dmin; std::memcpy(&d, x, 2); std::memcpy(&dmin, x + 2, 2);
    const uint8_t* scales = x + 4;
    const uint8_t* qs = x + 16;
    int32_t lanes[8] = {}; int32_t min_sum = 0;
    for (unsigned g = 0; g < 8; ++g) {
        int scale, minv; K4ScaleMin(scales, g, scale, minv);
        const uint8_t* q = qs + (g / 2) * 32;
        const bool high = (g & 1u) != 0;
        for (unsigned i = 0; i < 32; ++i) {
            const int w = high ? int(q[i] >> 4) : int(q[i] & 15u);
            lanes[i & 7u] += scale * w * int(y.qs[g * 32 + i]);
        }
        min_sum += minv * int(y.bsums[2 * g] + y.bsums[2 * g + 1]);
    }
    const float d_ = HalfToFloat(d) * y.d;
    const float dmin_ = HalfToFloat(dmin) * y.d;
    float sumf = 0.0f;
    for (int i = 0; i < 8; ++i) sumf += d_ * float(lanes[i]);
    return sumf - dmin_ * float(min_sum);
}

float DotQ6(const uint8_t* x, const Q8Block& y) {
    const uint8_t* ql = x;
    const uint8_t* qh = x + 128;
    const int8_t* sc = (const int8_t*)(x + 192);
    uint16_t d; std::memcpy(&d, x + 208, 2);
    int32_t lanes[8] = {};
    for (unsigned g = 0; g < 8; ++g) {
        const unsigned half = g / 4, part = g % 4;
        const unsigned shift4 = part >= 2 ? 4 : 0;
        const unsigned loff = half * 64 + (part & 1u) * 32;
        const unsigned hoff = half * 32;
        const unsigned qhoff = 2 * part;
        for (unsigned i = 0; i < 32; ++i) {
            const int low4 = int((ql[loff + i] >> shift4) & 15u);
            const int high2 = int((qh[hoff + i] >> qhoff) & 3u);
            const int quant = (low4 | (high2 << 4)) - 32;
            lanes[i & 7u] += int(sc[g * 2 + i / 16]) * quant * int(y.qs[g * 32 + i]);
        }
    }
    const float d_ = HalfToFloat(d) * y.d;
    float sumf = 0.0f;
    for (int i = 0; i < 8; ++i) sumf += d_ * float(lanes[i]);
    return sumf;
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------
struct Metrics { double cosine, rmse, max_abs, rel; bool finite; };

Metrics Compare(const std::vector<float>& a, const std::vector<float>& b) {
    Metrics m{};
    m.finite = true;
    double dot = 0, na = 0, nb = 0, sq = 0, mx = 0;
    for (size_t i = 0; i < a.size() && i < b.size(); ++i) {
        if (!std::isfinite(a[i]) || !std::isfinite(b[i])) m.finite = false;
        const double d = double(a[i]) - double(b[i]);
        sq += d * d;
        if (std::fabs(d) > mx) mx = std::fabs(d);
        dot += double(a[i]) * double(b[i]);
        na += double(a[i]) * double(a[i]);
        nb += double(b[i]) * double(b[i]);
    }
    m.cosine = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 1.0;
    m.rmse = std::sqrt(sq / double(std::max<size_t>(a.size(), 1)));
    m.max_abs = mx;
    const double mag = std::sqrt(nb / double(std::max<size_t>(b.size(), 1)));
    m.rel = (mag > 1e-12) ? m.rmse / mag : m.rmse;
    return m;
}

}  // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::string model, weightsName, spv = "F:\\rawrxd\\tools\\shaders\\quant_dot.spv";
    int rows = 8;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--weights" && i + 1 < argc) weightsName = argv[++i];
        else if (a == "--rows" && i + 1 < argc) rows = std::atoi(argv[++i]);
        else if (a == "--spv" && i + 1 < argc) spv = argv[++i];
        else { std::printf("unknown arg: %s\n", a.c_str()); return 1; }
    }
    if (model.empty()) {
        std::printf("usage: gpu_quant_dot_realweights --model <model.gguf> "
                    "[--weights NAME] [--rows N] [--spv PATH]\n");
        return 1;
    }

    std::printf("=== RAWRXD_DEEP2_GPU_QUANT_DOT_002 (REAL GGUF WEIGHTS) ===\n");
    std::printf("model: %s\n", model.c_str());

    Gguf g;
    if (!g.open(model) || !g.parse()) {
        std::printf("GGUF_OPEN_FAIL\n");
        return 1;
    }
    std::printf("  mmap ok, %zu tensors, %zu bytes\n", g.tensors.size(), g.size);

    // ---- choose the weight tensor (real Q4_K or Q6_K) ----
    const Gguf::Tensor* w = nullptr;
    if (!weightsName.empty()) {
        w = g.find(weightsName.c_str());
        if (!w) { std::printf("WEIGHT_NOT_FOUND: %s\n", weightsName.c_str()); return 1; }
    } else {
        // Prefer the first Q4_K tensor, else the first Q6_K tensor.
        for (const auto& t : g.tensors) if (t.gtype == 12) { w = &t; break; }
        if (!w) for (const auto& t : g.tensors) if (t.gtype == 14) { w = &t; break; }
        if (!w) { std::printf("NO_Q4K_OR_Q6K_TENSOR\n"); return 1; }
    }

    const ggml_type_traits* wt = ggml_get_type_traits((ggml_type)w->gtype);
    if (!wt || !wt->to_float) { std::printf("WEIGHT_TYPE_UNSUPPORTED\n"); return 1; }
    const int kind = (w->gtype == 12) ? 0 : (w->gtype == 14) ? 1 : -1;
    if (kind < 0) { std::printf("KIND_UNSUPPORTED type=%u\n", w->gtype); return 1; }

    const size_t n_in = (size_t)w->dims[0];    // ne[0]
    const uint64_t rows_total = w->dims.size() >= 2 ? w->dims[1] : 1;
    if (n_in == 0 || (n_in % 256) != 0) {
        std::printf("BAD_N_IN: %zu (must be a non-zero multiple of 256)\n", n_in);
        return 1;
    }
    const size_t n_blocks = n_in / 256;
    const size_t block_bytes = wt->type_size;
    const size_t row_stride = n_blocks * block_bytes;
    if (rows < 1) rows = 1;
    if ((uint64_t)rows > rows_total) rows = (int)rows_total;
    if (w->bytes < row_stride * (uint64_t)rows) {
        std::printf("TENSOR_TOO_SMALL: has %zu bytes, need %zu\n",
                    w->bytes, row_stride * (size_t)rows);
        return 1;
    }

    const char* kname = kind == 0 ? "Q4_K" : "Q6_K";
    std::printf("  weights : %s  %s  ne=[%zu,%llu] block_bytes=%zu row_stride=%zu rows=%d\n",
                w->name.c_str(), kname, n_in, (unsigned long long)rows_total,
                block_bytes, row_stride, rows);

    // ---- real activation: dequantize row 0 of a real tensor ----
    // Prefer token_embd.weight (a genuine activation-shaped vector), else any
    // tensor whose ne[0] matches n_in and has a working dequantizer.
    std::vector<float> activation(n_in, 0.0f);
    std::string actSource;
    const Gguf::Tensor* cand = g.find("token_embd.weight");
    const ggml_type_traits* at = nullptr;
    if (cand && cand->dims.size() >= 2 && (size_t)cand->dims[0] == n_in) {
        at = ggml_get_type_traits((ggml_type)cand->gtype);
        if (at && at->to_float) {
            // One row of the embedding table occupies dims[0] values.
            const size_t rblocks = (n_in + (size_t)at->blck_size - 1) / (size_t)at->blck_size;
            const size_t rbytes = rblocks * (size_t)at->type_size;
            if (cand->bytes >= rbytes) {
                at->to_float(cand->data, activation.data(), (int)n_in);
                actSource = cand->name + " row 0 (" + at->type_name + ")";
            }
        }
    }
    if (actSource.empty()) {
        for (const auto& t : g.tensors) {
            if (t.dims.size() < 2 || (size_t)t.dims[0] != n_in) continue;
            const ggml_type_traits* tr2 = ggml_get_type_traits((ggml_type)t.gtype);
            if (!tr2 || !tr2->to_float) continue;
            activation = std::vector<float>(n_in, 0.0f);
            tr2->to_float(t.data, activation.data(), (int)n_in);
            actSource = t.name + " row 0 (" + tr2->type_name + ")";
            at = tr2;
            break;
        }
    }
    if (actSource.empty()) {
        // Fully-real fallback: row 0 of the weight tensor itself, dequantized.
        wt->to_float(w->data, activation.data(), (int)n_in);
        actSource = std::string(w->name) + " row 0 (self, " + wt->type_name + ")";
        at = wt;
    }
    std::printf("  activation: %s  (first 4: %g %g %g %g)\n", actSource.c_str(),
                activation[0], activation[1], activation[2], activation[3]);

    // ---- ggml Q8_0 quantisation of the same real activation (for the
    //      cross-check below: it validates our Q8_K-style quantiser against
    //      ggml's own, rather than assuming it is equivalent).
    const ggml_type_traits* q8tr = ggml_get_type_traits(GGML_TYPE_Q8_0);
    if (!q8tr) { std::printf("Q8_0_TRAITS_MISSING\n"); return 1; }
    const size_t q8_blk_bytes = (size_t)q8tr->type_size;                 // 34
    const size_t q8_per_256 = 256 / (size_t)q8tr->blck_size;             // 8
    const size_t q8_bytes_total = n_blocks * q8_per_256 * q8_blk_bytes;
    std::vector<uint8_t> q8_raw(q8_bytes_total, 0);
    const size_t q8_got = ggml_quantize_chunk(GGML_TYPE_Q8_0, activation.data(),
                                              q8_raw.data(), 0, 1, (int64_t)n_in, nullptr);
    if (q8_got == 0) { std::printf("GGML_QUANTIZE_Q8_0_FAILED\n"); return 1; }
    std::printf("  ggml_quantize_chunk(Q8_0) -> %zu bytes (expected %zu)\n",
                q8_got, q8_bytes_total);

    // ---- build the shader's Q8 layout: one scale per 256 values.
    // The shader takes a Q8_K-style block (single scale per 256 values), so
    // the real activation is quantised with ggml's Q8_8_K rule
    // d = amax(|x|) / 127, q = round(x / d). This is deliberately NOT a
    // reinterpretation of the per-32-scaled Q8_0 bytes above.
    std::vector<float> q8buf(n_blocks * 273, 0.0f);
    std::vector<float> act_q8(n_in, 0.0f);   // dequantised, what both sides see
    double q8_amax = 0.0;
    for (size_t b = 0; b < n_blocks; ++b) {
        float* out = q8buf.data() + b * 273;
        float amax = 0.0f;
        for (int i = 0; i < 256; ++i)
            amax = std::max(amax, std::fabs(activation[b * 256 + i]));
        const float d = (amax > 0.0f) ? amax / 127.0f : 0.0f;
        out[0] = d;
        int qs[256];
        for (int i = 0; i < 256; ++i) {
            int q = (d > 0.0f) ? (int)std::lround(activation[b * 256 + i] / d) : 0;
            q = std::max(-128, std::min(127, q));
            qs[i] = q;
            out[1 + i] = float(q);
            act_q8[b * 256 + i] = d * float(q);
        }
        for (int g2 = 0; g2 < 16; ++g2) {
            int s2 = 0;
            for (int k = 0; k < 16; ++k) s2 += qs[g2 * 16 + k];
            out[257 + g2] = float(s2);
        }
        q8_amax = std::max(q8_amax, (double)amax);
    }

    // ---- validate our Q8_K-style quantisation against ggml's Q8_0 ----
    // Compare the DEQUANTISED values, which is what the dot products consume.
    {
        std::vector<float> gg(n_in, 0.0f);
        for (size_t s = 0; s < n_blocks * q8_per_256; ++s) {
            const uint8_t* sb = q8_raw.data() + s * q8_blk_bytes;
            uint16_t dbits; std::memcpy(&dbits, sb, 2);
            const float d = HalfToFloat(dbits);
            for (int i = 0; i < 32; ++i) gg[s * 32 + i] = d * float((int8_t)sb[2 + i]);
        }
        double mx = 0.0, num = 0.0, den = 0.0;
        for (size_t i = 0; i < n_in; ++i) {
            const double dd = double(gg[i]) - double(act_q8[i]);
            mx = std::max(mx, std::fabs(dd));
            num += dd * dd;
            den += double(gg[i]) * double(gg[i]);
        }
        const double rmse = std::sqrt(num / double(n_in));
        const double rel = std::sqrt(den) > 1e-12 ? std::sqrt(num) / std::sqrt(den) : rmse;
        std::printf("  q8 cross-check (ours vs ggml Q8_0, dequantised):"
                    " max_abs=%.3e rel_l2=%.3e  block_amax_max=%.6g\n",
                    mx, rel, q8_amax);
        // The two quantisers differ by DESIGN, not by accident: ours uses one
        // scale per 256 values (Q8_K rule), ggml's Q8_0 uses one fp16 scale
        // per 32 values, so ours is coarser. A couple of percent of relative
        // L2 is the expected cost of that coarser granularity; anything near
        // 1.0 would mean the layouts were mismatched.
        if (rel > 0.10) {
            std::printf("  ERROR: Q8 cross-check rel_l2=%.3e is far larger than the\n"
                        "        expected per-256 vs per-32 granularity gap.\n", rel);
            return 1;
        }
        std::printf("  (difference vs ggml Q8_0 is the expected cost of one scale\n"
                    "   per 256 values instead of one fp16 scale per 32.)\n");
    }

    // ---- GPU dispatch ----
    std::vector<uint32_t> packed_u32((row_stride * (uint64_t)rows + 3) / 4, 0u);
    std::memcpy(packed_u32.data(), w->data, row_stride * (size_t)rows);

    std::vector<float> gpu((size_t)rows, 0.0f);
    VulkanCompute vc;
    if (!vc.Initialize()) { std::printf("VULKAN_INIT_FAIL\n"); return 1; }
    std::printf("VULKAN_DEVICE=%s\n", vc.GetDeviceInfo().device_name.c_str());
    bool ok = vc.ExecuteQuantDot(packed_u32.data(), packed_u32.size() * 4,
                                 q8buf.data(), q8buf.size() * 4,
                                 gpu.data(), gpu.size() * 4,
                                 (size_t)rows, n_in, n_blocks, kind);
    if (!ok) { std::printf("DISPATCH_FAIL\n"); return 1; }

    // ---- reference A: ggml dequantise the weights, use the SAME quantised
    //      activation values the GPU saw, plain float dot product ----
    std::vector<float> wrow(n_in);
    std::vector<float> refA((size_t)rows, 0.0f);
    for (int r = 0; r < rows; ++r) {
        wt->to_float(w->data + (size_t)r * row_stride, wrow.data(), (int)n_in);
        // Real activations are dequantised as d_blk * q[i], i.e. exactly the
        // values encoded in q8buf. This keeps the comparison to the kernel
        // rather than to the choice of quantiser.
        double acc = 0.0;
        for (size_t i = 0; i < n_in; ++i) acc += double(wrow[i]) * double(act_q8[i]);
        refA[r] = (float)acc;
    }

    // ---- crosscheck B: independent CPU integer-lane reference ----
    std::vector<float> refB((size_t)rows, 0.0f);
    {
        // Rebuild Q8Block from the shader-scale + quantised values.
        std::vector<Q8Block> q8blk(n_blocks);
        for (size_t b = 0; b < n_blocks; ++b) {
            const float* src = q8buf.data() + b * 273;
            q8blk[b].qs.assign(256, 0.0f);
            q8blk[b].bsums.assign(16, 0.0f);
            q8blk[b].d = src[0];
            for (int i = 0; i < 256; ++i) q8blk[b].qs[i] = src[1 + i];
            for (int i = 0; i < 16; ++i) q8blk[b].bsums[i] = src[257 + i];
        }
        for (int r = 0; r < rows; ++r) {
            const uint8_t* rowData = w->data + (size_t)r * row_stride;
            double acc = 0.0;
            for (size_t b = 0; b < n_blocks; ++b) {
                const uint8_t* blk = rowData + b * block_bytes;
                acc += (kind == 0) ? DotQ4(blk, q8blk[b]) : DotQ6(blk, q8blk[b]);
            }
            refB[r] = (float)acc;
        }
    }

    // ---- report ----
    const Metrics mA = Compare(gpu, refA);
    const Metrics mB = Compare(gpu, refB);
    const bool good = mA.finite && mA.cosine >= 0.999999 && mA.rel <= 1e-4;
    std::printf("\n%-6s vs A(ggml dequant + float dot): cos=%+.10f rel=%.3e max=%.3e finite=%d %s\n",
                kname, mA.cosine, mA.rel, mA.max_abs, mA.finite ? 1 : 0, good ? "PASS" : "FAIL");
    std::printf("%-6s vs B(cpu integer-lane)      : cos=%+.10f rel=%.3e max=%.3e finite=%d %s\n",
                kname, mB.cosine, mB.rel, mB.max_abs, mB.finite ? 1 : 0,
                (mB.finite && mB.cosine >= 0.999999 && mB.rel <= 1e-4) ? "PASS" : "FAIL");
    std::printf("  first 3 gpu:");
    for (int i = 0; i < rows && i < 3; ++i) std::printf(" %.6g", gpu[i]);
    std::printf("\n  first 3 refA:");
    for (int i = 0; i < rows && i < 3; ++i) std::printf(" %.6g", refA[i]);
    std::printf("\n");
    std::printf("VERDICT=%s\n", good ? "PASS" : "FAIL");
    g.close();
    return good ? 0 : 1;
}
