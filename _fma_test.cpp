// RAWRXD_DEEP2_TPS_AND_CERTIFICATION_RECOVERY: quant-dot kernel isolation.
//
// The parity gate went from a (vacuous) perfect PASS to a FAIL the moment the
// "CPU reference" executor was pinned to the CPU path for real. The only code
// that differs between the two executors is QuantDot::DotBlocked: GPU shader
// vs the CpuDot lambda. This tool compares BOTH against an independent
// dequantised double-precision reference on REAL GGUF tensors, so the wrong
// path is identified without the transformer stack in the way.
//
// It is a diagnostic tool: it prints and exits, writes nothing.

#include "src/deep2/modelgenie/universal_gguf.hpp"
#include "src/deep2/runtime_graph_executor.hpp"
#include "src/deep2/quant_dot_dispatch.hpp"
#include "include/vulkan_compute.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::Universal::IngestReport;
using RawrXD::Deep2::Universal::TensorRec;
using RawrXD::Deep2::QuantDot::DotBlocked;
using RawrXD::Deep2::QuantDot::CpuDot;
using RawrXD::Deep2::RuntimeGraph::Executor;

static uint32_t g_seed = 12345u;
static float NextRand() {
    // xorshift32 -> roughly uniform in [-1, 1]
    g_seed ^= g_seed << 13; g_seed ^= g_seed >> 17; g_seed ^= g_seed << 5;
    return (float)((double)(g_seed % 20001u) / 10000.0 - 1.0);
}

// OpLinear's Q8_K interleaved activation: per 256 values [d, qs[256], bsums[16]].
static void QuantizeQ8Interleaved(const std::vector<float>& x, std::vector<float>& q8) {
    const size_t n_in = x.size();
    const size_t n_blk = n_in / 256;
    q8.assign(n_blk * 273, 0.0f);
    for (size_t b = 0; b < n_blk; ++b) {
        float mx = 0.0f;
        for (size_t i = 0; i < 256; ++i) mx = std::max(mx, std::fabs(x[b * 256 + i]));
        const float d = mx / 127.0f;
        const float inv = d > 0.0f ? 1.0f / d : 0.0f;
        float* blk = q8.data() + b * 273;
        blk[0] = d;
        int32_t bsums[16] = {0};
        for (size_t i = 0; i < 256; ++i) {
            const int32_t v = (int32_t)std::lround(x[b * 256 + i] * inv);
            blk[1 + i] = (float)v;
            bsums[i / 16] += v;
        }
        for (size_t k = 0; k < 16; ++k) blk[257 + k] = (float)bsums[k];
    }
}

// The CPU dot under test: a verbatim copy of Executor::OpLinear's CpuDot lambda
// (the code the "CPU reference" parity path runs).
static CpuDot MakeCpuDot(size_t n_in, int kind) {
    return [n_in, kind](const uint8_t* row, const void* q8_act, size_t) -> float {
        const float* q8 = static_cast<const float*>(q8_act);
        const size_t nblk = n_in / 256;
        const size_t blk_bytes = (kind == 0) ? 144u : 210u;
        int32_t a[256];
        int32_t aux32[8];
        float sums[8], sumf = 0.0f;
        for (int l = 0; l < 8; ++l) sums[l] = 0.0f;
        for (size_t b = 0; b < nblk; ++b) {
            const uint8_t* blk = row + b * blk_bytes;
            const float* q8b = q8 + b * 273;
            for (int l = 0; l < 8; ++l) aux32[l] = 0;
            if (kind == 0) {
                for (int j = 0; j < 4; ++j) {
                    for (int l = 0; l < 32; ++l) {
                        a[j * 64 + l]      = blk[16 + j * 32 + l] & 0xF;
                        a[j * 64 + 32 + l] = blk[16 + j * 32 + l] >> 4;
                    }
                }
                int32_t scales[8], mins[8];
                for (int s = 0; s < 8; ++s) {
                    if (s < 4) {
                        scales[s] = blk[4 + s] & 63;
                        mins[s]   = blk[4 + s + 4] & 63;
                    } else {
                        scales[s] = (blk[4 + s + 4] & 0xF) | ((blk[4 + s - 4] >> 6) << 4);
                        mins[s]   = (blk[4 + s + 4] >> 4) | ((blk[4 + s] >> 6) << 4);
                    }
                }
                for (int s = 0; s < 8; ++s) {
                    const int32_t sc = scales[s];
                    for (int l = 0; l < 32; ++l)
                        aux32[l & 7] += sc * (int32_t)q8b[1 + s * 32 + l] * a[s * 32 + l];
                }
                uint16_t h;
                std::memcpy(&h, blk + 0, 2);
                const float d = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(h)) * q8b[0];
                std::memcpy(&h, blk + 2, 2);
                const float dmin = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(h)) * q8b[0];
                for (int l = 0; l < 8; ++l) sums[l] = std::fma(d, float(aux32[l]), sums[l]);
                int32_t sumi = 0;
                for (int j = 0; j < 16; ++j) sumi += (int32_t)q8b[257 + j] * mins[j / 2];
                sumf = std::fma(-dmin, float(sumi), sumf);
            } else {
                for (int j = 0; j < 256; ++j) a[j] = 0;
                for (int j = 0; j < 2; ++j) {          // 128-value halves
                    const uint8_t* q4 = blk + j * 64;
                    const uint8_t* qh = blk + 128 + j * 32;
                    int* ah = a + j * 128;
                    for (int l = 0; l < 32; ++l) {
                        ah[l +  0] = (int8_t)((q4[l +  0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
                        ah[l + 32] = (int8_t)((q4[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
                        ah[l + 64] = (int8_t)((q4[l +  0] >>  4) | (((qh[l] >> 4) & 3) << 4)) - 32;
                        ah[l + 96] = (int8_t)((q4[l + 32] >>  4) | (((qh[l] >> 6) & 3) << 4)) - 32;
                    }
                }
                int32_t scales[16];
                for (int s = 0; s < 16; ++s) {
                    int8_t sc;
                    std::memcpy(&sc, blk + 192 + s, 1);
                    scales[s] = sc;
                }
                for (int s = 0; s < 16; ++s) {
                    const int32_t sc = scales[s];
                    for (int l = 0; l < 16; ++l)
                        aux32[l & 7] += sc * (int32_t)q8b[1 + s * 16 + l] * a[s * 16 + l];
                }
                uint16_t h;
                std::memcpy(&h, blk + 208, 2);
                const float d = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(h)) * q8b[0];
                for (int l = 0; l < 8; ++l) sums[l] = std::fma(d, float(aux32[l]), sums[l]);
            }
        }
        for (int l = 0; l < 8; ++l) sumf = std::fma(1.0f, sums[l], sumf);
        return sumf;
    };
}

int main(int argc, char** argv) {
    // --fp16-test: compare the shader's manual half_to_float against ggml's
    // fp16->fp32 for ALL 65536 bit patterns. A subnormal-handling difference
    // would be a (bounded, sub-ULP-of-the-scale) source of per-dot error.
    if (argc > 1 && std::strcmp(argv[1], "--fp16-test") == 0) {
        auto shaderHalf = [](uint32_t h) -> float {
            const uint32_t sign = (h & 0x8000u) << 16;
            const uint32_t exp  = (h >> 10) & 31u;
            const uint32_t frac = h & 1023u;
            if (exp == 0u) {
                if (frac == 0u) {
                    uint32_t u = sign;
                    float f;
                    std::memcpy(&f, &u, 4);
                    return f;
                }
                uint32_t m = frac;
                int e = -14;
                while ((m & 1024u) == 0u) { m <<= 1; --e; }
                m &= 1023u;
                uint32_t u = sign | (uint32_t(e + 127) << 23) | (m << 13);
                float f;
                std::memcpy(&f, &u, 4);
                return f;
            }
            if (exp == 31u) {
                uint32_t u = sign | 0x7f800000u | (frac << 13);
                float f;
                std::memcpy(&f, &u, 4);
                return f;
            }
            uint32_t u = sign | ((exp + 112u) << 23) | (frac << 13);
            float f;
            std::memcpy(&f, &u, 4);
            return f;
        };
        size_t mismatches = 0;
        double worst = 0;
        uint16_t worst_bits = 0;
        for (uint32_t bits = 0; bits < 65536u; ++bits) {
            uint16_t hb = (uint16_t)bits;
            const float a = shaderHalf(bits);
            const float b = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(hb));
            if (a != b) {
                ++mismatches;
                const double d = std::fabs(double(a) - double(b));
                if (d > worst) { worst = d; worst_bits = hb; }
            }
        }
        std::printf("fp16 patterns=65536 mismatches=%zu worst_delta=%.9g (bits=0x%04x)\n",
                    mismatches, worst, worst_bits);
        // Print the first few mismatching patterns with both values.
        size_t shown = 0;
        for (uint32_t bits = 0; bits < 65536u && shown < 8; ++bits) {
            uint16_t hb = (uint16_t)bits;
            const float a = shaderHalf(bits);
            const float b = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(hb));
            if (a != b) {
                std::printf("  bits=0x%04x (exp=%u frac=%u sign=%u): shader=%.9g ggml=%.9g delta=%.3g\n",
                            hb, (bits >> 10) & 31u, bits & 1023u, (bits >> 15) & 1u,
                            a, b, double(a) - double(b));
                ++shown;
            }
        }
        // How many are subnormal vs normal?
        size_t sub = 0, nrm = 0;
        for (uint32_t bits = 0; bits < 65536u; ++bits) {
            uint16_t hb = (uint16_t)bits;
            const float a = shaderHalf(bits);
            const float b = ggml_fp16_to_fp32(static_cast<ggml_fp16_t>(hb));
            if (a != b) { if (((bits >> 10) & 31u) == 0u) ++sub; else ++nrm; }
        }
        std::printf("  mismatches: subnormal_exp=%zu normal_exp=%zu\n", sub, nrm);
        return mismatches == 0 ? 0 : 7;
    }

    // --first-divergence mode: two executors, identical graph, op-by-op
    // comparison until the first MATERIALLY divergent tensor.
    if (argc > 1 && std::strcmp(argv[1], "--first-divergence") == 0) {
        const char* model = argc > 2 ? argv[2] : "F:\\rawrxd\\models\\qwen2.5-coder_1.5b-base.gguf";
        const uint32_t tok = argc > 3 ? (uint32_t)std::strtoul(argv[3], nullptr, 10) : 100u;
        const int n_tokens = argc > 4 ? (int)std::strtol(argv[4], nullptr, 10) : 16;
        const IngestReport& rep = Ingest(model, false);
        if (rep.tensors.empty()) { std::printf("INGEST_FAILED\n"); return 2; }

        Executor ex;   // GPU path (default)
        Executor ref;  // CPU-pinned reference path
        ref.SetForceCpu(true);
        if (!ex.Bind(rep)) { std::printf("GPU_BIND_FAILED: %s\n", ex.LastError().c_str()); return 2; }
        if (!ref.Bind(rep)) { std::printf("REF_BIND_FAILED: %s\n", ref.LastError().c_str()); return 2; }
        ex.SetOpTrace(true, true);
        ref.SetOpTrace(true, true);

        // Teacher-forced multi-token decode: each position feeds a fixed
        // sequence so both executors see identical inputs, and traces are
        // compared per position to find where a divergence first MATERIALISES
        // (the single-token run agreed to 8e-6, so something amplifies across
        // positions - this localises it).
        int worst_pos = -1;
        double worst_mx = 0.0;
        size_t worst_op = 0;
        std::string worst_name;
        for (int t = 0; t < n_tokens; ++t) {
            const uint32_t tk = tok + (uint32_t)(t * 7919);   // deterministic spread
            const size_t g0 = ex.OpTraces().size();
            const size_t r0 = ref.OpTraces().size();
            const bool okEx = ex.ExecuteToken(tk, (size_t)t);
            const bool okRef = ref.ExecuteToken(tk, (size_t)t);
            if (!okEx || !okRef) {
                std::printf("execute token=%d gpu=%d ref=%d\n", t, okEx ? 1 : 0, okRef ? 1 : 0);
                if (!okEx) std::printf("gpu error: %s\n", ex.LastError().c_str());
                if (!okRef) std::printf("ref error: %s\n", ref.LastError().c_str());
                return 3;
            }
            const auto& te = ex.OpTraces();
            const auto& tr = ref.OpTraces();
            double pos_mx = 0.0;
            size_t pos_op = 0;
            std::string pos_name;
            for (size_t i = 0; i < te.size() - g0; ++i) {
                const size_t gi = g0 + i, ri = r0 + i;
                if (gi >= te.size() || ri >= tr.size()) break;
                if (te[gi].values.size() != tr[ri].values.size()) continue;
                double mx = 0;
                for (size_t k = 0; k < te[gi].values.size(); ++k)
                    mx = std::max(mx, std::fabs(double(te[gi].values[k]) - double(tr[ri].values[k])));
                if (mx > pos_mx) { pos_mx = mx; pos_op = gi; pos_name = te[gi].name; }
            }
            if (pos_mx > worst_mx) { worst_mx = pos_mx; worst_pos = t; worst_op = pos_op; worst_name = pos_name; }
            if (pos_mx > 1e-5) {
                std::printf("pos=%d ops=%zu max_op_delta=%.6g (op #%zu '%s')\n",
                            t, te.size() - g0, pos_mx, pos_op, pos_name.c_str());
                // Find the first op whose delta exceeds ARITHMETIC noise (1e-3)
                // and characterise it: a single wild element is structural, a
                // broad spread with tiny per-element ratio is rounding.
                for (size_t i = 0; i < te.size() - g0; ++i) {
                    const size_t gi = g0 + i, ri = r0 + i;
                    if (gi >= te.size() || ri >= tr.size()) break;
                    const auto& gv = te[gi].values;
                    const auto& rv = tr[ri].values;
                    if (gv.size() != rv.size() || gv.empty()) continue;
                    double mx = 0;
                    size_t ndiff = 0;
                    for (size_t k = 0; k < gv.size(); ++k) {
                        const double d = std::fabs(double(gv[k]) - double(rv[k]));
                        if (d > mx) mx = d;
                        if (d > 1e-3) ++ndiff;
                    }
                    if (mx <= 1e-3) continue;
                    size_t first_diff = (size_t)-1;
                    for (size_t k = 0; k < gv.size(); ++k) {
                        if (std::fabs(double(gv[k]) - double(rv[k])) > 1e-3) { first_diff = k; break; }
                    }
                    double ref_mag = 0;
                    for (float v : rv) ref_mag = std::max(ref_mag, std::fabs(double(v)));
                    std::printf("  MAT op #%zu name='%s' size=%zu delta=%.6g (%zu elems >1e-3, %.1f%%) first_idx=%llu\n",
                                gi, te[gi].name.c_str(), gv.size(), mx, ndiff,
                                100.0 * double(ndiff) / double(gv.size()),
                                (unsigned long long)(first_diff == (size_t)-1 ? 0 : first_diff));
                    std::printf("  tensor max|ref|=%.6g ; element ratio delta/|ref| ~ %.3g\n",
                                ref_mag, first_diff == (size_t)-1 ? 0.0 : mx / (std::fabs(rv[first_diff]) + 1e-9));

                    // ---- ISOLATED REPLAY (decisive): reproduce THIS op outside
                    // the network. Extract the exact input (its producer's
                    // captured values), quantise exactly as OpLinear does, run
                    // GPU and CPU DotBlocked in isolation, and compare both to
                    // the traced outputs. If all three agree, the network
                    // divergence is roundoff amplification, not this kernel.
                    {
                        // find the producer: the nearest preceding op whose
                        // output name matches this op's input name.
                        const std::string& inName = te[gi].input;
                        long long producer = -1;
                        if (!inName.empty() && inName[0] != '<') {
                            for (long long j = (long long)gi - 1; j >= 0 && j >= (long long)gi - 6; --j) {
                                if (te[j].name == inName) { producer = j; break; }
                            }
                        }
                        const TensorRec* wt = nullptr;
                        for (const TensorRec& tt : rep.tensors) {
                            if (tt.name == te[gi].weight) { wt = &tt; break; }
                        }
                        std::printf("  REPLAY: weight='%s' input='%s'(producer op #%lld) kind=%d\n",
                                    te[gi].weight.c_str(), inName.c_str(), producer,
                                    wt ? ((wt->ggml_type == GGML_TYPE_Q4_K) ? 0 : (wt->ggml_type == GGML_TYPE_Q6_K) ? 1 : -1) : -1);
                        if (producer >= 0 && wt) {
                            const int kind = (wt->ggml_type == GGML_TYPE_Q4_K) ? 0
                                          : (wt->ggml_type == GGML_TYPE_Q6_K) ? 1 : -1;
                            const std::vector<float>& xin = te[(size_t)producer].values;
                            const size_t n_in = wt->dims.empty() ? 0 : wt->dims[0];
                            const size_t n_out = wt->dims.size() > 1 ? wt->dims[1] : 0;
                            std::printf("  REPLAY geometry: n_in=%zu n_out=%zu xin=%zu ggml_type=%d\n",
                                        n_in, n_out, xin.size(), (int)wt->ggml_type);
                            if (kind >= 0 && n_in && n_out && (n_in % 256 == 0) &&
                                xin.size() >= n_in) {
                                std::vector<float> x(xin.begin(), xin.begin() + n_in);
                                std::vector<float> q8;
                                QuantizeQ8Interleaved(x, q8);
                                std::vector<float> y_gpu(n_out, 0.0f), y_cpu(n_out, 0.0f);
                                const bool okG = DotBlocked(kind, wt->data, wt->bytes, x.data(), n_in,
                                                            y_gpu.data(), n_out,
                                                            MakeCpuDot(n_in, kind),
                                                            q8.data(), q8.size() * sizeof(float), false);
                                const bool okC = DotBlocked(kind, wt->data, wt->bytes, x.data(), n_in,
                                                            y_cpu.data(), n_out,
                                                            MakeCpuDot(n_in, kind),
                                                            q8.data(), q8.size() * sizeof(float), true);
                                double iso = 0;
                                for (size_t k = 0; k < n_out; ++k)
                                    iso = std::max(iso, std::fabs(double(y_gpu[k]) - double(y_cpu[k])));
                                double vsTracedGpu = 0, vsTracedRef = 0;
                                for (size_t k = 0; k < n_out && k < gv.size() && k < rv.size(); ++k) {
                                    vsTracedGpu = std::max(vsTracedGpu, std::fabs(double(y_gpu[k]) - double(gv[k])));
                                    vsTracedRef = std::max(vsTracedRef, std::fabs(double(y_cpu[k]) - double(rv[k])));
                                }
                                std::printf("  REPLAY RESULT: okG=%d okC=%d isolated_gpu_vs_cpu_max=%.6g\n",
                                            okG ? 1 : 0, okC ? 1 : 0, iso);
                                std::printf("  REPLAY vs traced: replayGpu_vs_netGpu=%.6g replayCpu_vs_netRef=%.6g (network delta was %.6g)\n",
                                            vsTracedGpu, vsTracedRef, mx);
                                if (iso <= 1e-6 && vsTracedGpu <= 1e-6 && vsTracedRef <= 1e-6)
                                    std::printf("  REPLAY VERDICT: kernel reproduces network output exactly; network divergence is roundoff amplification, NOT a kernel defect\n");
                                else if (iso <= 1e-6)
                                    std::printf("  REPLAY VERDICT: isolated GPU==CPU bit-exact but differs from BOTH traced outputs -> the network fed a DIFFERENT input/weight than replayed\n");
                                else
                                    std::printf("  REPLAY VERDICT: isolated GPU != CPU on this exact input -> kernel-level divergence on real activation\n");
                                return 6;
                            } else {
                                std::printf("  REPLAY SKIPPED: geometry/kind unsupported\n");
                            }
                        } else {
                            std::printf("  REPLAY SKIPPED: producer/weight not resolvable\n");
                        }
                    }
                    break;   // only the first material op per position
                }
            }
        }
        std::printf("WORST pos=%d max_op_delta=%.6g at op #%zu '%s'\n",
                    worst_pos, worst_mx, worst_op, worst_name.c_str());
        // Final logits comparison.
        {
            const auto& gl = ex.Logits();
            const auto& rl = ref.Logits();
            double dot = 0, na = 0, nb = 0, mx = 0;
            for (size_t i = 0; i < std::min(gl.size(), rl.size()); ++i) {
                const double d = double(gl[i]) - double(rl[i]);
                mx = std::max(mx, std::fabs(d));
                dot += double(gl[i]) * double(rl[i]);
                na += double(gl[i]) * double(gl[i]);
                nb += double(rl[i]) * double(rl[i]);
            }
            const double cos = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
            std::printf("logits: n=%zu cos=%.10f max_abs=%.6f\n", gl.size(), cos, mx);
        }
        return 0;
    }

    const char* model = argc > 1 ? argv[1] : "F:\\rawrxd\\models\\qwen2.5-coder_1.5b-base.gguf";
    const char* want_name = argc > 2 ? argv[2] : "blk.0.attn_q.weight";
    const IngestReport& rep = Ingest(model, false);
    if (rep.tensors.empty()) { std::printf("INGEST_FAILED\n"); return 2; }

    const TensorRec* w = nullptr;
    for (const TensorRec& t : rep.tensors) {
        if (t.name == want_name) { w = &t; break; }
    }
    if (!w) {
        std::printf("TENSOR_NOT_FOUND: %s\n", want_name);
        std::printf("first tensors:");
        for (size_t i = 0; i < rep.tensors.size() && i < 10; ++i)
            std::printf(" %s", rep.tensors[i].name.c_str());
        std::printf("\n");
        return 2;
    }

    const int kind = (w->ggml_type == GGML_TYPE_Q4_K) ? 0 : (w->ggml_type == GGML_TYPE_Q6_K) ? 1 : -1;
    std::printf("tensor=%s ggml_type=%d kind=%d dims=[%zu,%zu] bytes=%zu\n",
                w->name.c_str(), (int)w->ggml_type, kind,
                w->dims.empty() ? 0 : w->dims[0],
                w->dims.size() > 1 ? w->dims[1] : 0, w->bytes);
    if (kind < 0) { std::printf("NOT_A_K_QUANT_TENSOR (kernel unsupported)\n"); return 3; }

    const size_t n_in = w->dims.empty() ? 0 : w->dims[0];
    const size_t n_out = w->dims.size() > 1 ? w->dims[1] : 0;
    if (n_in == 0 || n_out == 0 || (n_in % 256) != 0) {
        std::printf("BAD_GEOMETRY n_in=%zu n_out=%zu\n", n_in, n_out);
        return 3;
    }
    const size_t n_blk = n_in / 256;
    const size_t row_bytes = n_blk * (kind == 0 ? 144u : 210u);
    if (w->bytes < row_bytes * n_out) {
        std::printf("SHORT_WEIGHT bytes=%zu need=%zu\n", w->bytes, row_bytes * n_out);
        return 3;
    }

    // Deterministic activation.
    std::vector<float> x(n_in, 0.0f);
    for (size_t i = 0; i < n_in; ++i) x[i] = NextRand() * 0.5f;

    std::vector<float> q8;
    QuantizeQ8Interleaved(x, q8);

    // --- GPU path -----------------------------------------------------------
    std::vector<float> y_gpu(n_out, 0.0f);
    const bool gpuOk = DotBlocked(kind, w->data, w->bytes, x.data(), n_in,
                                  y_gpu.data(), n_out, MakeCpuDot(n_in, kind),
                                  q8.data(), q8.size() * sizeof(float), false);

    // --- CPU lambda path (what the parity "reference" runs) -----------------
    std::vector<float> y_cpu(n_out, 0.0f);
    const bool cpuOk = DotBlocked(kind, w->data, w->bytes, x.data(), n_in,
                                  y_cpu.data(), n_out, MakeCpuDot(n_in, kind),
                                  q8.data(), q8.size() * sizeof(float), true);

    // --- independent reference: dequantised weight x RAW float x, double ----
    std::vector<float> y_ref(n_out, 0.0f);
    const ggml_type_traits* tr = ggml_get_type_traits(w->ggml_type);
    std::vector<float> rw(n_in, 0.0f);
    for (size_t j = 0; j < n_out; ++j) {
        const uint8_t* row = reinterpret_cast<const uint8_t*>(w->data) + j * row_bytes;
        tr->to_float(row, rw.data(), (int)n_in);
        double acc = 0.0;
        for (size_t i = 0; i < n_in; ++i) acc += double(rw[i]) * double(x[i]);
        y_ref[j] = (float)acc;
    }

    // --- path C: dequantised weight x DEQUANTISED Q8_K activation -----------
    // The same quantised activation the two kernels consumed, unfolded back to
    // floats: xq_recon[i] = d_block * qs[i]. If A == B == C, the quantised
    // arithmetic is right and the A/B-vs-D delta is pure activation
    // quantisation error, not a kernel defect. If B != C, the shared
    // quant-dot arithmetic has a layout/indexing defect.
    std::vector<float> xq(n_in, 0.0f);
    for (size_t b = 0; b < n_blk; ++b) {
        const float d = q8[b * 273 + 0];
        for (size_t i = 0; i < 256; ++i) xq[b * 256 + i] = d * q8[b * 273 + 1 + i];
    }
    std::vector<float> y_q8ref(n_out, 0.0f);
    for (size_t j = 0; j < n_out; ++j) {
        const uint8_t* row = reinterpret_cast<const uint8_t*>(w->data) + j * row_bytes;
        tr->to_float(row, rw.data(), (int)n_in);
        double acc = 0.0;
        for (size_t i = 0; i < n_in; ++i) acc += double(rw[i]) * double(xq[i]);
        y_q8ref[j] = (float)acc;
    }

    std::printf("gpuOk=%d cpuOk=%d n_in=%zu n_out=%zu n_blk=%zu row_bytes=%zu\n",
                gpuOk ? 1 : 0, cpuOk ? 1 : 0, n_in, n_out, n_blk, row_bytes);
    std::printf("row0: gpu=% .6f cpu=% .6f ref=% .6f\n", y_gpu[0], y_cpu[0], y_ref[0]);

    auto compare = [](const char* tag, const std::vector<float>& a,
                      const std::vector<float>& b) {
        double dot = 0, na = 0, nb = 0, mx = 0, sq = 0;
        size_t first_bad = (size_t)-1;
        for (size_t i = 0; i < a.size(); ++i) {
            const double d = double(a[i]) - double(b[i]);
            sq += d * d; mx = std::max(mx, std::fabs(d));
            if (first_bad == (size_t)-1 && std::fabs(d) > 1e-3) first_bad = i;
            dot += double(a[i]) * double(b[i]);
            na += double(a[i]) * double(a[i]);
            nb += double(b[i]) * double(b[i]);
        }
        const double cos = (na > 0 && nb > 0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;
        const double rms = std::sqrt(sq / double(a.size()));
        std::printf("%s: cos=%.9f rms=%.9g max_abs=%.9g first_diff_row=%s%lld\n", tag, cos, rms, mx,
                    first_bad == (size_t)-1 ? "" : "",
                    first_bad == (size_t)-1 ? -1LL : (long long)first_bad);
    };
    if (gpuOk) compare("gpu_vs_cpu_lambda", y_gpu, y_cpu);
    if (gpuOk) compare("gpu_vs_ref_dequant", y_gpu, y_ref);
    if (cpuOk) compare("cpu_lambda_vs_ref ", y_cpu, y_ref);
    // The decisive four-path table: A gpu, B cpu lambda, C dequant x dequant(Q8),
    // D dequant x FP32.  A=B established; C vs B decides kernel-vs-quantisation.
    if (cpuOk) compare("cpu_lambda_vs_q8ref", y_cpu, y_q8ref);
    if (gpuOk) compare("gpu_vs_q8ref       ", y_gpu, y_q8ref);
    compare("q8ref_vs_ref_dequant", y_q8ref, y_ref);   // pure Q8 activation error

    // --- per-block partial sums for row 0 (layout forensics) -----------------
    {
        const uint8_t* row = reinterpret_cast<const uint8_t*>(w->data);
        const float* q8b = q8.data();
        std::printf("row0 block0 forensics: q8 d=%.6f first qs=%.0f bsums[0..3]=%.0f,%.0f,%.0f,%.0f\n",
                    q8b[0], q8b[1], q8b[257], q8b[258], q8b[259], q8b[260]);
        std::printf("row0 block0 weight: blk[0..7]=%u,%u,%u,%u,%u,%u,%u,%u (fp16 d,dmin at 0,2; scales at 4..11; mins at 12..15; ql at 16..)\n",
                    row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]);
    }
    return 0;
}


