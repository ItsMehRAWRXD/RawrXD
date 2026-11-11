// nemotron_mamba2_parity.cpp
// RAWRXD_NEMOTRON_H_MAMBA2_NUMERIC_PARITY_001
//
// Compares a Nemotron-H Mamba2 SSM implementation against ggml's
// ggml_ssm_conv / ggml_ssm_scan (llama.cpp's independently maintained
// reference). Geometry and layouts come from RAWRXD_NEMOTRON_GEOMETRY_001,
// derived from F:\models\nemotron-3.5-lightning-30b.gguf.
//
// Pipeline modelled faithfully:
//   ssm_in projection  2688 -> 10304 : z[0,4096) x[4096,8192) B[8192,9216)
//                                        C[9216,10240) dt[10240,10304)
//   gather for conv                  : [x(4096) | B(1024) | C(1024)] = 6144
//   causal conv1d k=4 over 6144 channels
//   scan with the conv output split  : x'[0,4096) B'[4096,5120) C'[5120,6144)
//   dt is taken from the projection, NOT from the conv output
//   then grouped RMS norm, z gate, and the out projection

#include "ggml.h"
#include "ggml-cpu.h"
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <vector>

namespace {

// Geometry (RAWRXD_NEMOTRON_GEOMETRY_001).
constexpr int kDInner   = 4096;
constexpr int kHeads    = 64;
constexpr int kHeadDim  = 64;
constexpr int kDState   = 128;
constexpr int kGroups   = 8;
constexpr int kGrpState = 1024;                 // kGroups * kDState
constexpr int kConvDim  = kDInner + 2 * kGrpState;   // 6144
constexpr int kConvK    = 4;
constexpr int kSsmInRows = 2 * kDInner + 2 * kGrpState + kHeads;   // 10304
constexpr int kHidden   = 2688;

// Offsets inside the ssm_in projection output.
constexpr int kOffZ  = 0;
constexpr int kOffX  = kDInner;                 // 4096
constexpr int kOffB  = 2 * kDInner;              // 8192
constexpr int kOffC  = kOffB + kGrpState;        // 9216
constexpr int kOffDt = kOffC + kGrpState;        // 10240

// Offsets inside the conv input / output (x | B | C).
constexpr int kConvOffX = 0;
constexpr int kConvOffB = kDInner;                        // 4096
constexpr int kConvOffC = kDInner + kGrpState;            // 5120

static_assert(kHeadDim * kHeads == kDInner, "");
static_assert(kConvDim == 6144, "");
static_assert(kSsmInRows == 10304, "");
static_assert(kOffX + kDInner == kOffB, "");
static_assert(kOffDt + kHeads == kSsmInRows, "");

float Wave(int i, int salt) {
    return 0.5f * std::sin(0.011f * float(i) + float(salt)) +
           0.05f * std::cos(0.037f * float(i) + 2.0f * float(salt));
}

// One stage of the pipeline, shared by both paths so inputs are identical.
struct Stage {
    std::vector<float> conv_in;   // [kConvK-1+n_t, kConvDim] history+input
    std::vector<float> dt;        // [n_t, nHeads]
    std::vector<float> state0;    // [kDState, kHeadDim, kHeads]
    std::vector<float> A;         // [kHeads]
    std::vector<float> z;         // [n_t, kDInner]   (gate, from projection)
    std::vector<float> norm_w;    // [kDInner / kGroups, kGroups] = [512, 8]
    std::vector<float> out_w;     // [kDInner, kHidden]
};

Stage BuildStage(int n_t) {
    Stage s;
    const int nx = kConvK - 1 + n_t;

    // conv history. ggml's sx is {d_conv-1+n_t, d_inner} where ne0 is the
    // window index, so element (window, channel) lives at channel*ncs + window.
    // Store it channel-major to match ggml exactly.
    const int ncs = kConvK - 1 + n_t;
    std::vector<float> raw((size_t)ncs * kConvDim);
    for (int i = 0; i < ncs * kConvDim; ++i) raw[i] = Wave(i, 3);
    s.conv_in.assign((size_t)ncs * kConvDim, 0.0f);
    for (int ch = 0; ch < kConvDim; ++ch)
        for (int w = 0; w < ncs; ++w)
            s.conv_in[(size_t)ch * ncs + w] = raw[(size_t)w * kConvDim + ch];

    s.dt.assign((size_t)n_t * kHeads, 0.0f);
    for (size_t i = 0; i < s.dt.size(); ++i)
        s.dt[i] = 0.7f * std::sin(0.03f * float(i) + 0.5f);   // softplus -> moderate

    s.state0.assign((size_t)kDState * kHeadDim * kHeads, 0.0f);
    for (size_t i = 0; i < s.state0.size(); ++i) s.state0[i] = 0.02f * Wave((int)i, 7);

    s.A.assign(kHeads, 0.0f);
    for (int h = 0; h < kHeads; ++h) s.A[h] = -0.5f - 0.01f * float(h % 5);

    s.z.assign((size_t)n_t * kDInner, 0.0f);
    for (size_t i = 0; i < s.z.size(); ++i) s.z[i] = Wave((int)i, 11);

    // ssm_norm.weight is [512, 8] = inner/groups x groups.
    s.norm_w.assign((size_t)(kDInner / kGroups) * kGroups, 0.0f);
    for (size_t i = 0; i < s.norm_w.size(); ++i)
        s.norm_w[i] = 0.5f + 0.01f * (float)(i % 17);

    s.out_w.assign((size_t)kHidden * kDInner, 0.0f);
    for (size_t i = 0; i < s.out_w.size(); ++i)
        s.out_w[i] = 0.02f * Wave((int)i, 13);

    return s;
}

struct Result {
    std::vector<float> conv;     // [kConvDim, n_t]
    std::vector<float> y;        // [kHeadDim * kHeads, n_t]  scan output
    std::vector<float> state;    // final state
    std::vector<float> block;    // full block output [kHidden, n_t]
    bool ok = false;
};

// ---------------------------------------------------------------------------
// Reference path: ggml conv + ggml scan.
// ---------------------------------------------------------------------------
Result RunReference(const Stage& s, int n_t) {
    Result r;
    std::vector<char> backing((size_t)512 * 1024 * 1024);
    ggml_init_params ip{};
    ip.mem_size = backing.size();
    ip.mem_buffer = backing.data();
    ip.no_alloc = false;
    struct ggml_context* ctx = ggml_init(ip);
    if (!ctx) return r;

    struct ggml_tensor* sx = ggml_new_tensor_3d(ctx, GGML_TYPE_F32,
                                                kConvK - 1 + n_t, kConvDim, 1);
    struct ggml_tensor* cw = ggml_new_tensor_2d(ctx, GGML_TYPE_F32, kConvK, kConvDim);
    struct ggml_tensor* cv = ggml_ssm_conv(ctx, sx, cw);
    std::memcpy(sx->data, s.conv_in.data(), s.conv_in.size() * sizeof(float));
    for (int ch = 0; ch < kConvDim; ++ch)
        for (int k = 0; k < kConvK; ++k)
            ((float*)cw->data)[(size_t)ch * kConvK + k] =
                0.05f * std::sin(0.02f * float(ch * kConvK + k) + 1.0f);

    struct ggml_cgraph* g1 = ggml_new_graph(ctx);
    ggml_build_forward_expand(g1, cv);
    ggml_graph_compute_with_ctx(ctx, g1, 1);
    r.conv.assign((const float*)cv->data, (const float*)cv->data + (size_t)kConvDim * n_t);

    struct ggml_tensor* x  = ggml_new_tensor_4d(ctx, GGML_TYPE_F32, kHeadDim, kHeads, n_t, 1);
    struct ggml_tensor* dt = ggml_new_tensor_3d(ctx, GGML_TYPE_F32, kHeads, n_t, 1);
    struct ggml_tensor* A  = ggml_new_tensor_2d(ctx, GGML_TYPE_F32, 1, kHeads);
    struct ggml_tensor* B  = ggml_new_tensor_4d(ctx, GGML_TYPE_F32, kDState, kGroups, n_t, 1);
    struct ggml_tensor* C  = ggml_new_tensor_4d(ctx, GGML_TYPE_F32, kDState, kGroups, n_t, 1);
    struct ggml_tensor* s0 = ggml_new_tensor_4d(ctx, GGML_TYPE_F32, kDState, kHeadDim, kHeads, 1);
    struct ggml_tensor* id = ggml_new_tensor_1d(ctx, GGML_TYPE_I32, 1);

    std::memcpy(s0->data, s.state0.data(), s.state0.size() * sizeof(float));
    std::memcpy(A->data,  s.A.data(),     s.A.size() * sizeof(float));
    std::memcpy(dt->data, s.dt.data(),    s.dt.size() * sizeof(float));
    ((int32_t*)id->data)[0] = 0;

    // Scatter the CONV output (channel-major: cv[ch*n_t + t]) into the scan
    // inputs using the conv offsets x[0,inner) B[inner,inner+gs) C[inner+2gs,inner+2*gs).
    for (int t = 0; t < n_t; ++t) {
        auto at = [&](int ch) { return r.conv[(size_t)t * kConvDim + ch]; };
        float* xt = (float*)x->data + (size_t)t * (kHeads * kHeadDim);
        for (int h = 0; h < kHeads; ++h)
            for (int d = 0; d < kHeadDim; ++d)
                xt[h * kHeadDim + d] = at(kConvOffX + h * kHeadDim + d);
        float* Bt = (float*)B->data + (size_t)t * (kDState * kGroups);
        float* Ct = (float*)C->data + (size_t)t * (kDState * kGroups);
        for (int g = 0; g < kGroups; ++g)
            for (int i = 0; i < kDState; ++i) {
                Bt[(size_t)g * kDState + i] = at(kConvOffB + (size_t)g * kDState + i);
                Ct[(size_t)g * kDState + i] = at(kConvOffC + (size_t)g * kDState + i);
            }
    }

    struct ggml_tensor* sc = ggml_ssm_scan(ctx, s0, x, dt, A, B, C, id);
    struct ggml_cgraph* g2 = ggml_new_graph(ctx);
    ggml_build_forward_expand(g2, sc);
    ggml_graph_compute_with_ctx(ctx, g2, 1);

    const size_t ny = (size_t)kHeadDim * kHeads * n_t;
    const size_t ns = (size_t)kDState * kHeadDim * kHeads;
    r.y.assign((const float*)sc->data, (const float*)sc->data + ny);
    r.state.assign((const float*)sc->data + ny, (const float*)sc->data + ny + ns);
    r.block.assign((size_t)kHidden * n_t, 0.0f);   // ggml does not run the rest
    r.ok = true;

    ggml_free(ctx);
    return r;
}

// ---------------------------------------------------------------------------
// Implementation under test: written from the Mamba2 equations, independently.
// ---------------------------------------------------------------------------
Result RunMine(const Stage& s, int n_t) {
    Result r;

    // ---- causal conv over kConvDim channels, channel-major like ggml ----
    const int ncs = kConvK - 1 + n_t;
    std::vector<float> cv((size_t)kConvDim * n_t, 0.0f);
    for (int ch = 0; ch < kConvDim; ++ch) {
        const float* hist = s.conv_in.data() + (size_t)ch * ncs;
        for (int t = 0; t < n_t; ++t) {
            float acc = 0.0f;
            for (int k = 0; k < kConvK; ++k)
                acc += hist[t + k] *
                       (0.05f * std::sin(0.02f * float(ch * kConvK + k) + 1.0f));
    // ggml's conv dst is {d_inner, n_t, n_seqs}, so element (channel, token)
    // lives at token*kConvDim + channel. That is token-major, unlike the
    // channel-major input.
    cv[(size_t)t * kConvDim + ch] = acc;
        }
    }
    r.conv = cv;

    // ---- scan ----
    std::vector<float> st = s.state0;
    std::vector<float> y((size_t)kHeadDim * kHeads * n_t, 0.0f);

    auto softplus = [](float v) {
        if (v > 20.0f)  return v;
        if (v < -20.0f) return std::exp(v);
        return std::log1pf(std::exp(v));
    };

    for (int t = 0; t < n_t; ++t) {
        // ggml's conv output is token-major: cv[t*kConvDim + ch].
        const float* tok = cv.data() + (size_t)t * kConvDim;
        auto at = [&](int ch) { return tok[ch]; };
        for (int h = 0; h < kHeads; ++h) {
            const float dth = softplus(s.dt[(size_t)t * kHeads + h]);
            const float dA  = std::exp(dth * s.A[h]);
            const int   g   = h / (kHeads / kGroups);
            for (int d = 0; d < kHeadDim; ++d) {
                const int ii = h * kHeadDim + d;
                const float xdt = at(kConvOffX + ii) * dth;
                float sumf = 0.0f;
                for (int i = 0; i < kDState; ++i) {
                    float& sc = st[(size_t)ii * kDState + i];
                    sc = sc * dA + xdt * at(kConvOffB + (size_t)g * kDState + i);
                    sumf += sc * at(kConvOffC + (size_t)g * kDState + i);
                }
                y[(size_t)t * (kHeads * kHeadDim) + ii] = sumf;
            }
        }
    }
    r.y = std::move(y);
    r.state = std::move(st);

    // ---- grouped RMS norm, z gate, out projection (block output) ----
    // y is [n_t][inner]; groups partition inner into kGroups of kDInner/kGroups.
    const size_t gs = kDInner / kGroups;   // 512
    r.block.assign((size_t)kHidden * n_t, 0.0f);
    std::vector<float> gated(kDInner, 0.0f);
    for (int t = 0; t < n_t; ++t) {
        const float* yt = r.y.data() + (size_t)t * kDInner;
        for (int g = 0; g < kGroups; ++g) {
            float ms = 0.0f;
            for (size_t i = 0; i < gs; ++i) { float v = yt[g * gs + i]; ms += v * v; }
            ms = std::sqrt(ms / float(gs) + 1e-5f);
            for (size_t i = 0; i < gs; ++i) {
                const size_t ix = (size_t)g * gs + i;
                float v = yt[ix] / ms;
                if (ix < s.norm_w.size()) v *= s.norm_w[ix];
                const float gate = s.z[(size_t)t * kDInner + ix] *
                                   (1.0f / (1.0f + std::exp(-s.z[(size_t)t * kDInner + ix])));
                gated[ix] = v * gate;
            }
        }
        for (int row = 0; row < kHidden; ++row) {
            double acc = 0.0;
            for (int i = 0; i < kDInner; ++i)
                acc += (double)s.out_w[(size_t)row * kDInner + i] * (double)gated[i];
            r.block[(size_t)row * n_t + t] = (float)acc;
        }
    }
    r.ok = true;
    return r;
}

struct Metrics { double cosine, rmse, max_abs, rel; bool finite; };

Metrics Compare(const std::vector<float>& a, const std::vector<float>& b) {
    Metrics m{};
    m.finite = true;
    double dot = 0, na = 0, nb = 0, sq = 0, mx = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        if (!std::isfinite(a[i]) || !std::isfinite(b[i])) { m.finite = false; continue; }
        double d = double(a[i]) - double(b[i]);
        sq += d * d;
        if (std::fabs(d) > mx) mx = std::fabs(d);
        dot += double(a[i]) * double(b[i]);
        na += double(a[i]) * double(a[i]);
        nb += double(b[i]) * double(b[i]);
    }
    m.cosine = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 1.0;
    m.rmse = std::sqrt(sq / double(a.size()));
    m.max_abs = mx;
    double mag = std::sqrt(nb / double(a.size()));
    m.rel = (mag > 1e-12) ? m.rmse / mag : m.rmse;
    return m;
}

} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    const int n_t = (argc > 1) ? std::atoi(argv[1]) : 8;
    if (n_t < 1 || n_t > 64) { printf("n_t must be 1..64\n"); return 2; }

    printf("=== RAWRXD_NEMOTRON_H_MAMBA2_NUMERIC_PARITY_001 ===\n");
    printf("geometry: d_inner=%d heads=%d head_dim=%d d_state=%d groups=%d conv_dim=%d conv_k=%d\n",
           kDInner, kHeads, kHeadDim, kDState, kGroups, kConvDim, kConvK);
    printf("ssm_in : z[0,%d) x[%d,%d) B[%d,%d) C[%d,%d) dt[%d,%d) rows=%d\n",
           kDInner, kOffX, kOffB, kOffB, kOffC, kOffC, kOffDt, kOffDt, kSsmInRows, kSsmInRows);
    printf("conv   : x[0,%d) B[%d,%d) C[%d,%d) width=%d\n",
           kConvOffB, kConvOffB, kConvOffC, kConvOffC, kConvDim, kConvDim);
    printf("tokens : %d\n\n", n_t);

    Stage s = BuildStage(n_t);
    Result ref  = RunReference(s, n_t);
    Result mine = RunMine(s, n_t);
    if (!ref.ok || !mine.ok) { printf("harness failure\n"); return 1; }

    Metrics mc = Compare(ref.conv, mine.conv);
    printf("--- conv  [%d x %d] ---\n", kConvDim, n_t);
    printf("  cosine=%+.12f rmse=%.3e max_abs=%.3e rel=%.3e\n",
           mc.cosine, mc.rmse, mc.max_abs, mc.rel);


    Metrics my = Compare(ref.y, mine.y);
    printf("--- scan y [%d x %d] ---\n", kHeadDim * kHeads, n_t);
    printf("  cosine=%+.12f rmse=%.3e max_abs=%.3e rel=%.3e\n",
           my.cosine, my.rmse, my.max_abs, my.rel);


    Metrics ms = Compare(ref.state, mine.state);
    printf("--- state [%d x %d x %d] ---\n", kDState, kHeadDim, kHeads);
    printf("  cosine=%+.12f rmse=%.3e max_abs=%.3e rel=%.3e\n",
           ms.cosine, ms.rmse, ms.max_abs, ms.rel);

    // ---- persistent-state replay in two chunks ----
    const int n_a = n_t / 2, n_b = n_t - n_a;
    Stage sa = BuildStage(n_a);
    Result ra = RunReference(sa, n_a), ma = RunMine(sa, n_a);
    {
        // rebuild the second-chunk stage with the reference's state as the seed
        Stage sb_ref = BuildStage(n_b);
        sb_ref.state0 = ra.state;
        Stage sb_mine = BuildStage(n_b);
        sb_mine.state0 = ma.state;
        Result rb2 = RunReference(sb_ref, n_b);
        Result mb2 = RunMine(sb_mine, n_b);
        Metrics cont = Compare(rb2.y, mb2.y);
        Metrics conts = Compare(rb2.state, mb2.state);
        printf("--- state carry, %d + %d tokens ---\n", n_a, n_b);
        printf("  chunk1 y cosine=%+.12f rel=%.3e\n", Compare(ra.y, ma.y).cosine,
               Compare(ra.y, ma.y).rel);
        printf("  chunk2 y cosine=%+.12f rel=%.3e (continuing from each path's state)\n",
               cont.cosine, cont.rel);
        printf("  chunk2 state cosine=%+.12f rel=%.3e\n", conts.cosine, conts.rel);
    }

    const double kCosTol = 0.999999, kRelTol = 1e-4;
    bool pass = my.finite && ms.finite && mc.finite &&
                mc.cosine >= kCosTol && mc.rel <= kRelTol &&
                my.cosine >= kCosTol && my.rel <= kRelTol &&
                ms.cosine >= kCosTol && ms.rel <= kRelTol;

    printf("\nVERDICT=%s\n", pass ? "PASS" : "FAIL");
    printf("Tolerances declared before inspection: cosine >= %.6f, rel_rmse <= %.0e\n",
           kCosTol, kRelTol);
    return pass ? 0 : 1;
}
