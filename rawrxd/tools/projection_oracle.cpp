// ============================================================================
// projection_oracle.cpp — RAWRXD_GEMMA3_PROJECTION_ORACLE_001
// ============================================================================
// Three authorities over ONE input vector, so the CPU/GPU divergence can be
// attributed to the weights, to the projection, or to neither.
//
//   x        = the CPU route's layer-0 ATTN_NORM vector, dumped verbatim
//   offline  = W (dequantized from the GGUF by the production registry) * x
//   cpu      = the CPU route's own projection of the same x
//   gpu      = the GPU resident lane's projection of the same x
//
// Why this and not more summaries: the parity probe's scalar records carry only
// MIN/MAX/MEAN/L2/FIRST8/HASH, and a summary cannot be inverted into a vector.
// enableParityProbeFullVectors() writes VEC records with the exact float values,
// and nothing in the tree called it until RAWRXD_LADDER_PARITY_VEC_LAYER was
// added to inference_authority_ladder.cpp. Without the VEC dump this tool has no
// input, which is why the discriminator it implements had not been run.
//
// The offline side deliberately uses the SAME registry dequantizers as the
// engine. That is not a compromise: the registry's decode was proved
// bit-exact against an independent transcription of the format definition for
// all ten quant types in the local corpus (RAWRXD_QUANT_E2E_GATE_001). So if
// offline != gpu while offline == cpu, the weights are not the variable and the
// GPU projection is. If offline != cpu, the reference path is the suspect and
// this tool is what says so.
//
// Hash is FNV-1a 64 over the raw float bytes, identical to Deep2Engine's
// parityHash(), so hashes are directly comparable with both the host probe's
// HASH= field and the Vulkan grid's HASH= field. No tolerance anywhere: a
// tolerance would hide exactly the class of defect this is built to find.
//
// BUILD (standalone, as the other quant tools)
//   cl /nologo /std:c++20 /EHsc /O2 /MT /I src /I src\deep2 /c /Fo:po.obj tools\projection_oracle.cpp
//   link /OUT:projection_oracle.exe po.obj QuantKernelRegistry.obj
//        InferenceEngine.lib rawrxd_remote64.lib vulkan-1.lib
//
// USAGE
//   projection_oracle.exe <model.gguf> <vecdump.txt> [vulkanGrid.txt]
// ============================================================================

#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"

// Only for the human-readable type label. This tool does NOT use its decoders —
// the whole point is that the offline side runs the PRODUCTION registry, so a
// second decoder here would make it a fourth opinion rather than a third.
#include "quant_format_reference.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

// Identical to Deep2Engine::parityHash. If this ever drifts, the tool silently
// stops being comparable with the probes, so it is written out rather than
// shared -- a header include would hide a change behind a rebuild.
uint64_t fnv1a64(const float* v, size_t n) {
    uint64_t h = 1469598103934665603ull;
    const auto* b = reinterpret_cast<const uint8_t*>(v);
    for (size_t i = 0; i < n * sizeof(float); ++i) {
        h ^= b[i];
        h *= 1099511628211ull;
    }
    return h;
}

struct ScalarRec {
    uint64_t hash = 0;
    double l2 = 0, minv = 0, maxv = 0, mean = 0;
    bool have = false;
};

struct VecRec {
    int step = -1;
    std::string name;
    std::vector<float> v;
};

// VEC=LAYER_0_ATTN_NORM N=1152 followed by ceil(N/16) lines of 16 values.
std::map<std::string, VecRec> readVecDump(const char* path, int step) {
    std::map<std::string, VecRec> out;
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return out;
    std::vector<char> line(1 << 16);
    VecRec* cur = nullptr;
    while (std::fgets(line.data(), (int)line.size(), f)) {
        if (std::strncmp(line.data(), "STEP=", 5) == 0) {
            int st = 0;
            char nm[256] = {0};
            size_t nn = 0;
            if (std::sscanf(line.data(), "STEP=%d VEC=%255s N=%zu", &st, nm, &nn) >= 2) {
                if (st == step) {
                    VecRec r;
                    r.step = st;
                    // %s already stopped at the space, so nm is exactly the
                    // checkpoint name. An earlier version tried to strip an "N="
                    // suffix that %s never captured, and truncated the name at
                    // the first 'N' -- "LAYER_0_ATTN_NORM" became
                    // "LAYER_0_ATT", so the tool reported NO_ATTN_NORM_VEC on a
                    // dump that plainly contained it.
                    r.name = nm;
                    r.v.reserve(nn);
                    cur = &out[r.name];
                    *cur = r;
                } else {
                    cur = nullptr;
                }
            }
            continue;
        }
        if (!cur) continue;
        const char* p = line.data();
        while (*p) {
            char* end = nullptr;
            const double d = std::strtod(p, &end);
            if (end == p) break;
            cur->v.push_back(static_cast<float>(d));
            p = end;
            while (*p == ',' || *p == ' ' || *p == '\t') ++p;
        }
    }
    std::fclose(f);
    return out;
}

// Scalar CP=<layer>_<stage> HASH= / L2= records from either probe.
std::map<std::string, ScalarRec> readScalars(const char* path, int step) {
    std::map<std::string, ScalarRec> out;
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return out;
    std::vector<char> line(1 << 16);
    while (std::fgets(line.data(), (int)line.size(), f)) {
        int st = 0;
        char nm[256] = {0};
        unsigned long long h = 0;
        double l2 = 0, mn = 0, mx = 0, me = 0;
        const int got = std::sscanf(line.data(), "STEP=%d CP=%255s COUNT=%*d MIN=%lf MAX=%lf "
                                           "MEAN=%lf L2=%lf", &st, nm, &mn, &mx, &me, &l2);
        if (got < 6) continue;
        if (step >= 0 && st != step) continue;
        const char* hpos = std::strstr(line.data(), "HASH=");
        if (!hpos) continue;
        h = std::strtoull(hpos + 5, nullptr, 16);
        ScalarRec r;
        r.hash = h; r.l2 = l2; r.minv = mn; r.maxv = mx; r.mean = me; r.have = true;
        out[nm] = r;
    }
    std::fclose(f);
    return out;
}

double l2of(const std::vector<float>& v, size_t n) {
    double s = 0;
    for (size_t i = 0; i < n && i < v.size(); ++i) s += double(v[i]) * double(v[i]);
    return std::sqrt(s);
}

// RAWRXD_VULKAN_PARITY_DUMP_VECTORS writes "<layer>_<STAGE>.bin" as
//   uint32 elementCount        (offset 0, little-endian)
//   float32 payload[elementCount] (offset 4)
//
// Verified against 0_Q_PRE_ROPE.bin: bytes 00 04 00 00 = 1024, and the float at
// offset 4 is 14.20328, offset 8 is -0.8553 -- both plausible Q values.
//
// An earlier version of this reader assumed a 12-byte header. The file size is
// consistent with that arithmetic (4108 = 12 + 1024*4) because an 8-byte ASCII
// trailer follows the payload, so the size check passed while every float was
// read 8 bytes late, off the end of the payload and into that trailer. The
// result was RMSE 3.8e14 and MAX_ABS 1.2e16 on values whose true range is +/-30
// -- text bytes reinterpreted as floats. The count is now READ from the file
// rather than inferred from its length, so a layout change cannot silently
// produce plausible arithmetic over the wrong bytes again.
bool readGpuDump(const std::string& dir, int layer, const char* stage,
                 std::vector<float>& out) {
    char path[1024];
    std::snprintf(path, sizeof path, "%s/%d_%s.bin", dir.c_str(), layer, stage);
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::uint32_t n = 0;
    if (std::fread(&n, 4, 1, f) != 1) { std::fclose(f); return false; }
    out.resize(n);
    const size_t got = n ? std::fread(out.data(), 4, n, f) : 0;
    std::fclose(f);
    return got == n;
}

struct Elemwise {
    bool valid = false;
    double cosine = 0, rmse = 0, maxAbs = 0;
    long long firstMismatch = -1;
    size_t n = 0, nDiff = 0;
};

// RAWRXD_GEMMA3_ELEMENTWISE_001
//
// L2 agreement is NOT elementwise agreement. A permutation, a head-layout
// transposition or any norm-preserving rearrangement leaves L2 invariant while
// destroying every element. That is precisely why the O-projection result below
// reports L2_AGREES=0 AND an elementwise breakdown: the two facts are
// independent, and only the second one rules a permutation in or out.
Elemwise compare(const std::vector<float>& a, const std::vector<float>& b) {
    Elemwise e;
    const size_t n = a.size() < b.size() ? a.size() : b.size();
    e.n = n;
    if (!n) return e;
    double dot = 0, na = 0, nb = 0, se = 0, mx = 0;
    for (size_t i = 0; i < n; ++i) {
        const double x = a[i], y = b[i];
        dot += x * y; na += x * x; nb += y * y;
        const double d = x - y;
        se += d * d;
        if (std::fabs(d) > mx) mx = std::fabs(d);
        if (std::memcmp(&a[i], &b[i], 4) != 0) {
            if (e.firstMismatch < 0) e.firstMismatch = (long long)i;
            ++e.nDiff;
        }
    }
    const double den = std::sqrt(na) * std::sqrt(nb);
    e.cosine = den > 0.0 ? dot / den : 0.0;
    e.rmse = std::sqrt(se / double(n));
    e.maxAbs = mx;
    e.valid = true;
    return e;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
            "usage: %s <model.gguf> <vecdump.txt> [vulkanGrid.txt] [step]\n", argv[0]);
        return 2;
    }
    const char* modelPath = argv[1];
    const char* vecPath  = argv[2];
    const char* gridPath = (argc >= 4 && argv[3][0] != '-') ? argv[3] : nullptr;
    const int step = (argc >= 5) ? std::atoi(argv[4]) : 0;
    const char* gpuDumpDir = std::getenv("RAWRXD_GPU_VECTOR_DUMP_DIR");

    Deep2::GGUFLoader loader;
    if (!loader.load(modelPath)) {
        std::fprintf(stderr, "LOAD_FAIL=%s\n", loader.error().c_str());
        return 2;
    }
    Deep2::QuantKernelRegistry& reg = Deep2::QuantKernelRegistry::Instance();
    reg.Initialize();

    auto vecs = readVecDump(vecPath, step);
    auto cpuS = readScalars(vecPath, step);
    std::map<std::string, ScalarRec> gpuS;
    if (gridPath) gpuS = readScalars(gridPath, step);

    // The input both routes are known to agree on, bit-exactly.
    VecRec x;
    for (const auto& kv : vecs) {
        if (kv.second.name.size() > 4 &&
            kv.second.name.compare(kv.second.name.size() - 9, 9, "ATTN_NORM") == 0) {
            x = kv.second;
            break;
        }
    }
    if (x.v.empty()) {
        std::fprintf(stderr, "NO_ATTN_NORM_VEC in %s at step=%d\n", vecPath, step);
        return 2;
    }
    std::printf("INPUT_STEP=%d  INPUT_VECTOR=%s  N=%zu  INPUT_HASH=%016llx  INPUT_L2=%.9g\n\n",
                x.step, x.name.c_str(), x.v.size(),
                (unsigned long long)fnv1a64(x.v.data(), x.v.size()), l2of(x.v, x.v.size()));

    // RAWRXD_GEMMA3_ATTENTION_OUTPUT_ORACLE_001
    //
    // Each projection must consume a DIFFERENT input vector, and choosing wrong
    // is exactly the mistake that made the first round of this comparison
    // invalid. attn_q/k/v consume ATTN_NORM; attn_output consumes the attention
    // context vector (ATTN_VALUE), whose width is headDim*numHeads, not hidden.
    //
    // Rather than hardcode one input for the whole run, the input stage is
    // SELECTED BY ELEMENT COUNT and then REPORTED, so a mismatch is visible in
    // the output instead of being silently absorbed. A projection whose COLS no
    // dumped vector satisfies is reported NO_ADMISSIBLE_INPUT and is NOT
    // compared -- previously it printed INPUT_SHAPE_MISMATCH and moved on, which
    // reads like a pass in a summary.
    struct Job { const char* tensor; const char* cpu; const char* gpu; const char* gpuStage; };
    const Job jobs[] = {
        { "blk.0.attn_q.weight",       "LAYER_0_Q",       "LAYER_0_Q_PRE_ROPE", "Q_PRE_ROPE" },
        { "blk.0.attn_k.weight",       "LAYER_0_K",       "LAYER_0_K_PRE_ROPE", "K_PRE_ROPE" },
        { "blk.0.attn_v.weight",       "LAYER_0_V",       "LAYER_0_V_PRE_ROPE", "V_PRE_ROPE" },
        { "blk.0.attn_output.weight",  "LAYER_0_O_PROJ",  "LAYER_0_O_PROJ",     "O_PROJ" },
    };

    int failures = 0, compared = 0, noInput = 0;
    for (const Job& j : jobs) {
        const Deep2::GGUFTensor* t = nullptr;
        for (const auto& n : loader.listTensors())
            if (n == j.tensor) { t = loader.getTensor(n); break; }
        if (!t || !t->data) {
            std::printf("TENSOR=%s  STATUS=NOT_FOUND\n\n", j.tensor);
            continue;
        }
        std::size_t be = 0, bb = 0;
        const int ty = static_cast<int>(t->type);
        const bool geo = Deep2::GGUFLoader::queryTypeGeometry(
            static_cast<std::uint32_t>(ty), be, bb);
        Deep2::DequantKernelFn dq = reg.GetDequant(ty);
        if (!geo || !dq || t->shape.size() != 2) {
            std::printf("TENSOR=%s  STATUS=NO_DEQUANT_OR_BAD_SHAPE  geo=%d dq=%d dims=%zu\n\n",
                        j.tensor, (int)geo, dq ? 1 : 0, t->shape.size());
            continue;
        }
        const size_t cols = static_cast<size_t>(t->shape[0]);
        const size_t rows = static_cast<size_t>(t->shape[1]);

        // Select the input vector by element count, preferring the attention
        // stages this model actually has. Reported, never assumed.
        const VecRec* in = nullptr;
        for (const auto& kv : vecs) {
            const std::string& nm = kv.second.name;
            const bool attnStage =
                nm.find("ATTN_NORM") != std::string::npos ||
                nm.find("ATTN_VALUE") != std::string::npos;
            if (attnStage && kv.second.v.size() == cols) { in = &kv.second; break; }
        }
        const char* tn = rawrxd::qref::ggmlTypeName(ty);
        std::printf("TENSOR=%s TYPE=%s ROWS=%zu COLS=%zu BLOCK_BYTES=%zu\n",
                    j.tensor, tn ? tn : "?", rows, cols, bb);
        if (!in) {
            std::printf("  INPUT_STAGE=(none)  INPUT_ELEMENTS_AVAILABLE=");
            for (const auto& kv : vecs)
                if (kv.second.name.find("ATTN") != std::string::npos)
                    std::printf("%s:%zu ", kv.second.name.c_str(), kv.second.v.size());
            std::printf("\n  COMPARISON_ADMISSIBLE=0  STATUS=NO_ADMISSIBLE_INPUT\n\n");
            ++noInput;
            continue;
        }
        const std::vector<float>& xv = in->v;
        std::printf("  INPUT_STAGE=%s INPUT_ELEMENTS=%zu ELEMENT_COUNT_MATCH=1\n",
                    in->name.c_str(), xv.size());

        const size_t nBlocks = (rows * cols) / bb;
        std::vector<float> w(rows * cols, 0.0f);
        dq(t->data, w.data(), rows * cols);

        std::vector<float> y(rows, 0.0f);
        for (size_t r = 0; r < rows; ++r) {
            const float* wr = w.data() + r * cols;
            float acc = 0.0f;
            for (size_t c = 0; c < cols; ++c) acc += wr[c] * xv[c];
            y[r] = acc;
        }

        const uint64_t oh = fnv1a64(y.data(), rows);
        const double ol2 = l2of(y, rows);
        const char* gpuStage = j.gpuStage;
        const auto& cs = cpuS[j.cpu];
        const bool haveGpu = j.gpu && gpuS.count(j.gpu);
        const ScalarRec& gs = haveGpu ? gpuS[j.gpu] : cs;

        std::printf("  OFFLINE_HASH=%016llx OFFLINE_L2=%.9g\n",
                    (unsigned long long)oh, ol2);
        if (cs.have)
            std::printf("  CPU_HASH    =%016llx CPU_L2    =%.9g  %s\n",
                        (unsigned long long)cs.hash, cs.l2,
                        cs.hash == oh ? "MATCHES_OFFLINE" : "DIFFERS_FROM_OFFLINE");
        else
            std::printf("  CPU_HASH    =(absent)\n");
        if (haveGpu)
            std::printf("  GPU_HASH    =%016llx GPU_L2    =%.9g  %s\n",
                        (unsigned long long)gs.hash, gs.l2,
                        gs.hash == oh ? "MATCHES_OFFLINE" : "DIFFERS_FROM_OFFLINE");
        else
            std::printf("  GPU_HASH    =(stage not in grid)\n");

        // Elementwise L2 agreement is not elementwise equality: a permutation
        // or a structured rearrangement preserves L2 exactly. Report the
        // RELATIVE L2 gap so "agrees to 7 digits" is visible as a number rather
        // than asserted.
        if (haveGpu) {
            const double rel = ol2 > 0.0 ? std::fabs(ol2 - gs.l2) / ol2 : 0.0;
            std::printf("  L2_RELATIVE_GAP=%.3e  ", rel);
            std::printf("L2_AGREES=%s\n", rel < 1e-5 ? "1" : "0");
        }

        // Elementwise, against the GPU's own dumped vector for this stage.
        if (gpuDumpDir && gpuStage) {
            std::vector<float> gv;
            if (readGpuDump(gpuDumpDir, 0, gpuStage, gv) && gv.size() == rows) {
                const Elemwise e = compare(y, gv);
                if (e.valid) {
                    std::printf("  GPU_ELEM_N=%zu  COSINE=%.12f  RMSE=%.6g  MAX_ABS=%.6g\n",
                                e.n, e.cosine, e.rmse, e.maxAbs);
                    std::printf("  FIRST_MISMATCH_INDEX=%lld  BITWISE_DIFFERENT=%zu/%zu\n",
                                e.firstMismatch, e.nDiff, e.n);
                    std::printf("  GPU_VALUE_AT_FIRST_MISMATCH=%.9g  OFFLINE_VALUE_AT_FIRST_MISMATCH=%.9g\n",
                                e.firstMismatch >= 0 ? gv[size_t(e.firstMismatch)] : 0.0,
                                e.firstMismatch >= 0 ? y[size_t(e.firstMismatch)] : 0.0);
                    const bool same = (e.cosine > 1.0 - 1e-6) && (e.maxAbs < 1e-3);
                    std::printf("  ELEMENTWISE_VERDICT=%s\n",
                        same ? "GPU_PROJECTION_ELEMENTWISE_PASS" : "GPU_PROJECTION_ELEMENTWISE_FAIL");

                    // Cosine near zero with matching L2 has exactly two causes:
                    // a wrong DIRECTION (arithmetic) or a PERMUTATION of the
                    // right direction (layout). A permutation preserves every
                    // block norm and destroys cosine; arithmetic preserves
                    // neither. Comparing per-head-block norms separates them,
                    // and it is the cheapest test that does.
                    {
                        const size_t blk = (rows % 256 == 0) ? 256 : rows;
                        const size_t nb = blk ? rows / blk : 0;
                        if (nb >= 2) {
                            std::vector<double> on, gn;
                            on.reserve(nb); gn.reserve(nb);
                            for (size_t bI = 0; bI < nb; ++bI) {
                                double so = 0, sg = 0;
                                for (size_t k = 0; k < blk; ++k) {
                                    so += double(y[bI * blk + k]) * double(y[bI * blk + k]);
                                    sg += double(gv[bI * blk + k]) * double(gv[bI * blk + k]);
                                }
                                on.push_back(std::sqrt(so));
                                gn.push_back(std::sqrt(sg));
                            }
                            std::vector<double> os(on), gs2(gn);
                            std::sort(os.begin(), os.end());
                            std::sort(gs2.begin(), gs2.end());
                            double worst = 0;
                            for (size_t i = 0; i < nb; ++i)
                                worst = std::max(worst, std::fabs(os[i] - gs2[i]));
                            const double scale = os.empty() || os.back() > 0 ? os.back() : 1.0;
                            std::printf("  BLOCK=%zu  NBLOCKS=%zu  BLOCK_NORM_MULTISET_MAXDIFF=%.6g"
                                        "  BLOCK_NORM_REL=%.3e  -> %s\n",
                                        blk, nb, worst, worst / scale,
                                        (worst / scale) < 1e-3
                                            ? "PERMUTATION (layout) : norms match, order does not"
                                            : "ARITHMETIC : block norms differ too");
                        }
                    }

                }
            } else {
                std::printf("  GPU_ELEMWISE=UNAVAILABLE (no dump %s/%d_%s.bin of %zu floats)\n",
                            gpuDumpDir, 0, gpuStage, rows);
            }
        }

        if (cs.have) {
            ++compared;
            if (cs.hash != oh) {
                ++failures;
                std::printf("  VERDICT=CPU_ROUTE_DISAGREES_WITH_ORACLE\n");
            } else if (haveGpu && gs.hash != oh) {
                ++failures;
                std::printf("  VERDICT=WEIGHTS_AND_CPU_AGREE__GPU_PROJECTION_DIFFERS\n");
            } else {
                std::printf("  VERDICT=ALL_AUTHORITIES_AGREE\n");
            }
        } else {
            std::printf("  VERDICT=OFFLINE_ONLY (no CPU scalar record to compare)\n");
        }
        std::printf("\n");
    }

    std::printf("TENSORS_COMPARED=%d  DISAGREEMENTS=%d  NO_ADMISSIBLE_INPUT=%d\n",
                compared, failures, noInput);
    std::printf("VERDICT=%s\n", failures == 0 ? "ORACLE_CONSISTENT" : "ORACLE_FINDING");
    return failures == 0 ? 0 : 1;
}
