// mamba2_ref_probe.cpp - independent Mamba2 block-0 reference probe.
//
// RAWRXD_GATE7_HYBRID_001: isolates the first-divergent-tensor question for the
// Nemotron hybrid. It decodes the block-0 SSM weights straight from the GGUF
// with ggml's own dequantiser (a different decode path from the executor),
// consumes Deep2's dumped block-0 attn_norm output as the block input, and
// computes the whole Mamba2 mixer with independent float arithmetic:
//
//   zxbcdt = x @ ssm_in.weight          (z | x | B | C | dt, NVIDIA order)
//   conv    = causal depthwise conv1d over [x | B | C], SiLU on the output
//   dt      = softplus(dt + ssm_dt.bias)
//   state[h,j,n] = dt[h]*A[h]-scaled recurrence, y = C.state + D*x
//   out     = RmsNorm(y * silu(z)) * ssm_norm.weight
//
// The result is written as f32 and compared against Deep2's ssm_out dump.
//
// Usage: mamba2_ref_probe <model.gguf> <input_attn_norm.bin> <out_ssm_out.bin>
//        [--N 128] [--G 8] [--K 4]
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "ggml.h"
#include "gguf.h"

namespace {

// Decoded weight matrix/vector: `v` holds row-major elements with row width
// `ne0`; for a weight [ne0, ne1] element (i0, i1) sits at i1*ne0 + i0.
struct Decoded {
    std::vector<float> v;
    size_t ne0 = 0, ne1 = 1;
};

struct GgufFile {
    FILE* f = nullptr;
    gguf_context* ctx = nullptr;
    ~GgufFile() {
        if (f) std::fclose(f);
        if (ctx) gguf_free(ctx);
    }
};

bool LoadTensor(GgufFile& gf, const char* name, Decoded& out, size_t expectNe0,
                std::string& err) {
    const int64_t id = gguf_find_tensor(gf.ctx, name);
    if (id < 0) { err = std::string("missing tensor ") + name; return false; }
    const ggml_type ty = gguf_get_tensor_type(gf.ctx, id);
    std::fprintf(stderr, "[probe] %s: type=%d bytes=%zu\n", name, (int)ty, gguf_get_tensor_size(gf.ctx, id));
    const size_t bytes = gguf_get_tensor_size(gf.ctx, id);
    const size_t off = gguf_get_data_offset(gf.ctx) + gguf_get_tensor_offset(gf.ctx, id);
    std::vector<char> raw(bytes);
    if (std::fseek(gf.f, (long)off, SEEK_SET) != 0 ||
        std::fread(raw.data(), 1, bytes, gf.f) != bytes) {
        err = std::string("read failed for ") + name;
        return false;
    }
    if (ty == GGML_TYPE_F32) {
        out.v.resize(bytes / sizeof(float));
        std::memcpy(out.v.data(), raw.data(), bytes);
    } else {
        const ggml_type_traits* tr = ggml_get_type_traits(ty);
        if (!tr || !tr->to_float) { err = std::string("no dequantiser for ") + name; return false; }
        const size_t blocks = bytes / (size_t)tr->type_size;
        const size_t n = blocks * (size_t)tr->blck_size;
        out.v.assign(n, 0.0f);
        tr->to_float(raw.data(), out.v.data(), (int)n);
    }
    const size_t n = out.v.size();
    out.ne0 = expectNe0 ? expectNe0 : n;
    out.ne1 = expectNe0 ? (n / expectNe0) : 1;
    return true;
}

bool ReadFloats(const char* path, std::vector<float>& v) {
    FILE* f = std::fopen(path, "rb");
    if (!f) { std::fprintf(stderr, "cannot open %s\n", path); return false; }
    std::fseek(f, 0, SEEK_END);
    const long n = std::ftell(f) / (long)sizeof(float);
    std::fseek(f, 0, SEEK_SET);
    v.assign((size_t)n, 0.0f);
    const size_t got = std::fread(v.data(), sizeof(float), (size_t)n, f);
    std::fclose(f);
    return got == (size_t)n;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: %s <model.gguf> <input_attn_norm.bin> <out_ssm_out.bin> [--N 128] [--G 8] [--K 4]\n", argv[0]);
        return 1;
    }
    size_t N = 128, G = 8, K = 4;
    for (int i = 4; i < argc; ++i) {
        if (std::strcmp(argv[i], "--N") == 0 && i + 1 < argc) N = (size_t)std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--G") == 0 && i + 1 < argc) G = (size_t)std::atoi(argv[++i]);
        else if (std::strcmp(argv[i], "--K") == 0 && i + 1 < argc) K = (size_t)std::atoi(argv[++i]);
    }

    GgufFile gf;
    gf.f = std::fopen(argv[1], "rb");
    if (!gf.f) { std::fprintf(stderr, "cannot open model\n"); return 1; }
    gguf_init_params ip = {};
    gf.ctx = gguf_init_from_file(argv[1], ip);
    if (!gf.ctx) { std::fprintf(stderr, "gguf init failed\n"); return 1; }

    std::vector<float> x;
    if (!ReadFloats(argv[2], x)) return 1;
    const size_t hidden = x.size();

    std::string err;
    Decoded inW, convW, convB, A, Dv, DtB, NormW;
    if (!LoadTensor(gf, "blk.0.ssm_in.weight", inW, hidden, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }
    if (!LoadTensor(gf, "blk.0.ssm_conv1d.weight", convW, K, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }
    if (!LoadTensor(gf, "blk.0.ssm_conv1d.bias", convB, 0, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }
    if (!LoadTensor(gf, "blk.0.ssm_a", A, 0, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }
    if (!LoadTensor(gf, "blk.0.ssm_d", Dv, 0, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }
    if (!LoadTensor(gf, "blk.0.ssm_dt.bias", DtB, 0, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }
    if (!LoadTensor(gf, "blk.0.ssm_norm.weight", NormW, 0, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }

    // Geometry: in_proj width (rows of the decoded matrix give ne0 == hidden,
    // so ne1 is the in_proj output width), heads from ssm_a.
    const size_t inOut = inW.ne1;
    const size_t nHeads = A.v.size();
    if (nHeads == 0 || inOut <= nHeads) { std::fprintf(stderr, "bad geometry\n"); return 1; }
    const size_t Ntot = N * G;
    const size_t D = (inOut - nHeads - 2 * Ntot) / 2;   // 2*D + 2*N*G + nHeads = inOut
    if (D == 0 || D % nHeads != 0) {
        std::fprintf(stderr, "geometry mismatch: inOut=%zu nHeads=%zu N=%zu G=%zu\n", inOut, nHeads, N, G);
        return 1;
    }
    const size_t headDim = D / nHeads;
    const size_t dtOff = 2 * D + 2 * Ntot;
    std::printf("[probe] geometry: D=%zu N=%zu G=%zu K=%zu heads=%zu headDim=%zu convCh=%zu inOut=%zu\n",
                D, N, G, K, nHeads, headDim, D + 2 * Ntot, inOut);

    // ---- 1. in_proj (independent float matmul over the decoded weights) ----
    std::vector<float> zxbcdt(inOut, 0.0f);
    for (size_t j = 0; j < inOut; ++j) {
        const float* wcol = inW.v.data() + j * hidden;
        double acc = 0.0;
        for (size_t i = 0; i < hidden; ++i) acc += (double)x[i] * (double)wcol[i];
        zxbcdt[j] = (float)acc;
    }
    const float* z  = zxbcdt.data();
    const float* xz = zxbcdt.data() + D;
    const float* Bp = zxbcdt.data() + 2 * D;
    const float* Cp = zxbcdt.data() + 2 * D + Ntot;
    const float* dtp = zxbcdt.data() + dtOff;

    // ---- 2. causal conv over [x | B | C] (single token, zero history) -----
    const size_t convCh = D + 2 * Ntot;
    std::vector<float> convOut(convCh, 0.0f);
    std::vector<float> cur(convCh, 0.0f);
    for (size_t i = 0; i < D; ++i) cur[i] = xz[i];
    for (size_t i = 0; i < Ntot; ++i) { cur[D + i] = Bp[i]; cur[D + Ntot + i] = Cp[i]; }
    for (size_t c = 0; c < convCh; ++c) {
        const float acc = convW.v[c * K + (K - 1)] * cur[c] + convB.v[c];  // newest tap
        convOut[c] = acc / (1.0f + std::exp(-acc));
    }
    const float* xc = convOut.data();
    const float* Bc = convOut.data() + D;
    const float* Cc = convOut.data() + D + Ntot;

    // ---- 3. dt and 4. recurrence with a ZERO initial state -----------------
    std::vector<float> dt(nHeads, 0.0f);
    for (size_t h = 0; h < nHeads; ++h) {
        const float v = dtp[h] + DtB.v[h];
        dt[h] = (v > 20.0f) ? v : std::log1p(std::exp(v));
    }
    std::vector<float> y(D, 0.0f);
    const size_t headsPerGroup = nHeads / G;
    for (size_t h = 0; h < nHeads; ++h) {
        const size_t g = h / headsPerGroup;
        const float* Bg = Bc + g * N;
        const float* Cg = Cc + g * N;
        const float dh = Dv.v[h % Dv.v.size()];
        for (size_t j = 0; j < headDim; ++j) {
            // zero initial state: state = dt * x * B;  y = C.state + D*x
            float acc = 0.0f;
            const float xv = xc[h * headDim + j];
            for (size_t n = 0; n < N; ++n)
                acc += Cg[n] * (dt[h] * xv * Bg[n]);
            y[h * headDim + j] = acc + dh * xv;
        }
    }

    // ---- 5. z gate then the gated RMSNorm ----------------------------------
    for (size_t i = 0; i < D; ++i) y[i] = y[i] * (z[i] / (1.0f + std::exp(-z[i])));
    double ss = 0.0;
    for (size_t i = 0; i < D; ++i) ss += (double)y[i] * (double)y[i];
    const float rms = std::sqrt((float)(ss / (double)D) + 1e-5f);
    double outSs = 0.0, inSs = 0.0;
    for (size_t i = 0; i < D; ++i) { y[i] = y[i] / rms * NormW.v[i]; outSs += (double)y[i] * (double)y[i]; }
    for (size_t j = 0; j < inOut; ++j) inSs += (double)zxbcdt[j] * (double)zxbcdt[j];
    std::printf("[probe] out_rms=%.6f  in_proj_rms=%.6f  dt0=%.6f  A0=%.6f  y0=%.8f\n",
                std::sqrt(outSs / (double)D), std::sqrt(inSs / (double)inOut), dt[0],
                A.v.empty() ? 0.0 : A.v[0], y[0]);

    FILE* f = std::fopen(argv[3], "wb");
    if (!f) { std::fprintf(stderr, "cannot write %s\n", argv[3]); return 1; }
    std::fwrite(y.data(), sizeof(float), y.size(), f);
    std::fclose(f);
    std::printf("[probe] wrote %s (%zu floats)\n", argv[3], y.size());
    return 0;
}
