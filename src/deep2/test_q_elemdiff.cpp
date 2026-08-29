/*
 * test_q_elemdiff.cpp — BATCH2_Q_ELEMDIFF
 * Element-wise Q_PRE_ROPE_0 Deep2 vs llama + Q4_K block-dot on worst row.
 *
 * Usage:
 *   test_q_elemdiff.exe deep2_Q.bin llama_Q.bin [attn_norm.bin] [gguf] [out_dir]
 */
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#define MKDIR(p) mkdir((p), 0755)
#endif

namespace {

struct BlockQ4K {
    uint16_t d, dmin;
    uint8_t scales[12];
    uint8_t qs[128];
};
static_assert(sizeof(BlockQ4K) == 144, "q4k");

static bool loadF32(const char* path, std::vector<float>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz < 4 || (sz % 4) != 0) { std::fclose(f); return false; }
    out.resize((size_t)sz / 4);
    if (std::fread(out.data(), 1, (size_t)sz, f) != (size_t)sz) {
        std::fclose(f);
        return false;
    }
    std::fclose(f);
    return true;
}

static uint64_t fnv1a(const float* a, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        uint32_t bits = 0;
        std::memcpy(&bits, &a[i], 4);
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (8 * b)) & 0xFFu;
            h *= 1099511628211ull;
        }
    }
    return h;
}

static double l2norm(const float* a, size_t n) {
    double ss = 0;
    for (size_t i = 0; i < n; ++i) ss += (double)a[i] * (double)a[i];
    return std::sqrt(ss);
}

static float fp16ToF32(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1u;
    uint32_t exp = (h >> 10) & 0x1Fu;
    uint32_t mant = h & 0x3FFu;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) f = sign << 31;
        else {
            int e = -1;
            do { e++; mant <<= 1; } while (!(mant & 0x400u));
            mant &= 0x3FFu;
            f = (sign << 31) | ((uint32_t)(127 - 15 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFFu << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float r;
    std::memcpy(&r, &f, 4);
    return r;
}

static void ggmlGetScaleMinK4(int j, const uint8_t* q, uint8_t* d, uint8_t* m) {
    if (j < 4) {
        *d = q[j] & 63;
        *m = q[j + 4] & 63;
    } else {
        *d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
        *m = (q[j + 4] >> 4) | ((q[j - 0] >> 6) << 4);
    }
}

static void ggmlDequantBlock(const BlockQ4K& blk, float* y) {
    const uint8_t* q = blk.qs;
    const float d = fp16ToF32(blk.d);
    const float minv = fp16ToF32(blk.dmin);
    int is = 0;
    uint8_t sc, m;
    for (int j = 0; j < 256; j += 64) {
        ggmlGetScaleMinK4(is + 0, blk.scales, &sc, &m);
        const float d1 = d * sc, m1 = minv * m;
        ggmlGetScaleMinK4(is + 1, blk.scales, &sc, &m);
        const float d2 = d * sc, m2 = minv * m;
        for (int l = 0; l < 32; ++l) *y++ = d1 * (float)(q[l] & 0xF) - m1;
        for (int l = 0; l < 32; ++l) *y++ = d2 * (float)(q[l] >> 4) - m2;
        q += 32;
        is += 2;
    }
}

} // namespace

int main(int argc, char** argv) {
    const char* deep2Path = argc > 1 ? argv[1] : nullptr;
    const char* llamaPath = argc > 2 ? argv[2] : nullptr;
    const char* attnPath  = argc > 3 ? argv[3] : nullptr;
    const char* modelPath = argc > 4 ? argv[4]
        : R"(F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf)";
    const char* outDir = argc > 5 ? argv[5]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_Q_ELEMDIFF)";

    if (!deep2Path || !llamaPath) {
        std::fprintf(stderr, "usage: test_q_elemdiff deep2_Q.bin llama_Q.bin [attn_norm.bin] [gguf] [out_dir]\n");
        return 2;
    }
    MKDIR(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)");
    MKDIR(outDir);

    std::vector<float> d2, ll, attn;
    if (!loadF32(deep2Path, d2) || !loadF32(llamaPath, ll)) {
        std::fprintf(stderr, "LOAD_FAIL deep2=%s llama=%s\n", deep2Path, llamaPath);
        return 3;
    }
    if (d2.size() != ll.size()) {
        std::fprintf(stderr, "SIZE_MISMATCH deep2=%zu llama=%zu\n", d2.size(), ll.size());
        return 3;
    }
    const size_t n = d2.size();
    const uint64_t fnvD = fnv1a(d2.data(), n);
    const uint64_t fnvL = fnv1a(ll.data(), n);

    double maxAbs = 0, sumAbs = 0, sumSq = 0;
    size_t exact = 0, bitDiff = 0;
    int firstDiff = -1, largestIdx = -1;
    for (size_t i = 0; i < n; ++i) {
        uint32_t bd = 0, bl = 0;
        std::memcpy(&bd, &d2[i], 4);
        std::memcpy(&bl, &ll[i], 4);
        if (bd == bl) ++exact;
        else {
            ++bitDiff;
            if (firstDiff < 0) firstDiff = (int)i;
        }
        const double e = std::fabs((double)d2[i] - (double)ll[i]);
        sumAbs += e;
        sumSq += e * e;
        if (e > maxAbs) { maxAbs = e; largestIdx = (int)i; }
    }
    const double meanAbs = sumAbs / (double)n;
    const double rms = std::sqrt(sumSq / (double)n);

    // Histogram of error magnitudes (log buckets)
    size_t buckExact = exact;
    size_t buck1e10 = 0, buck1e8 = 0, buck1e6 = 0, buck1e4 = 0, buckBig = 0;
    for (size_t i = 0; i < n; ++i) {
        uint32_t bd = 0, bl = 0;
        std::memcpy(&bd, &d2[i], 4);
        std::memcpy(&bl, &ll[i], 4);
        if (bd == bl) continue;
        const double e = std::fabs((double)d2[i] - (double)ll[i]);
        if (e < 1e-10) ++buck1e10;
        else if (e < 1e-8) ++buck1e8;
        else if (e < 1e-6) ++buck1e6;
        else if (e < 1e-4) ++buck1e4;
        else ++buckBig;
    }

    // Periodicity: count diffs per 32 / 256 stride
    std::vector<size_t> diffPer32(32, 0), diffPer256(256, 0);
    for (size_t i = 0; i < n; ++i) {
        uint32_t bd = 0, bl = 0;
        std::memcpy(&bd, &d2[i], 4);
        std::memcpy(&bl, &ll[i], 4);
        if (bd == bl) continue;
        diffPer32[i % 32]++;
        diffPer256[i % 256]++;
    }

    FILE* vf = std::fopen((std::string(outDir) + "\\elemdiff_stats.txt").c_str(), "w");
    auto emit = [&](FILE* f) {
        std::fprintf(f, "n=%zu\n", n);
        std::fprintf(f, "deep2_fnv=%016llx l2=%.9e\n", (unsigned long long)fnvD, l2norm(d2.data(), n));
        std::fprintf(f, "llama_fnv=%016llx l2=%.9e\n", (unsigned long long)fnvL, l2norm(ll.data(), n));
        std::fprintf(f, "expect_llama_fnv=8d53927ede5ddb3f\n");
        std::fprintf(f, "expect_deep2_fnv_post_q8k=ced1abe971861249\n");
        std::fprintf(f, "max_abs_error=%.17g\n", maxAbs);
        std::fprintf(f, "mean_abs_error=%.17g\n", meanAbs);
        std::fprintf(f, "rms_error=%.17g\n", rms);
        std::fprintf(f, "number_exact_equal=%zu\n", exact);
        std::fprintf(f, "number_bitwise_different=%zu\n", bitDiff);
        std::fprintf(f, "first_different_index=%d\n", firstDiff);
        std::fprintf(f, "largest_error_index=%d\n", largestIdx);
        if (firstDiff >= 0) {
            std::fprintf(f, "first_diff deep2=%.9e llama=%.9e abs=%.9e\n",
                         (double)d2[(size_t)firstDiff], (double)ll[(size_t)firstDiff],
                         std::fabs((double)d2[(size_t)firstDiff] - (double)ll[(size_t)firstDiff]));
        }
        if (largestIdx >= 0) {
            std::fprintf(f, "largest_diff deep2=%.9e llama=%.9e abs=%.9e\n",
                         (double)d2[(size_t)largestIdx], (double)ll[(size_t)largestIdx],
                         std::fabs((double)d2[(size_t)largestIdx] - (double)ll[(size_t)largestIdx]));
        }
        std::fprintf(f, "error_buckets exact=%zu lt1e-10=%zu lt1e-8=%zu lt1e-6=%zu lt1e-4=%zu ge1e-4=%zu\n",
                     buckExact, buck1e10, buck1e8, buck1e6, buck1e4, buckBig);
        std::fprintf(f, "diff_mod32:");
        for (size_t i = 0; i < 32; ++i) std::fprintf(f, " %zu", diffPer32[i]);
        std::fprintf(f, "\n");
    };
    emit(stdout);
    if (vf) { emit(vf); }

    // Top-20 largest abs errors
    std::vector<int> order((int)n);
    for (int i = 0; i < (int)n; ++i) order[i] = i;
    std::sort(order.begin(), order.end(), [&](int a, int b) {
        double ea = std::fabs((double)d2[(size_t)a] - (double)ll[(size_t)a]);
        double eb = std::fabs((double)d2[(size_t)b] - (double)ll[(size_t)b]);
        return ea > eb;
    });
    FILE* top = std::fopen((std::string(outDir) + "\\elemdiff_top20.txt").c_str(), "w");
    if (top) {
        std::fprintf(top, "rank index deep2 llama abs_err\n");
        for (int r = 0; r < 20 && r < (int)n; ++r) {
            int i = order[r];
            double e = std::fabs((double)d2[(size_t)i] - (double)ll[(size_t)i]);
            std::fprintf(top, "%d %d %.9e %.9e %.9e\n", r, i, (double)d2[(size_t)i], (double)ll[(size_t)i], e);
        }
        std::fclose(top);
    }

    // Pattern classification
    const char* pattern = "unknown";
    if (bitDiff == 0) pattern = "IDENTICAL";
    else if (buckBig == 0 && buck1e4 == 0 && (buck1e6 + buck1e8 + buck1e10) == bitDiff)
        pattern = "many_tiny_fp_diffs";
    else if (buckBig > 0 && buckBig < 16)
        pattern = "few_isolated_large";
    else if (buckBig > 100)
        pattern = "many_large_or_structured";
    else
        pattern = "mixed_precision_and_sparse";

    // Optional: block-dot for largest / first row using frozen ATTN_NORM + attn_q
    if (attnPath && loadF32(attnPath, attn) && attn.size() == 2048 && n == 2048) {
        Deep2::GGUFLoadOptions opt;
        auto lr = Deep2::GGUFLoader::Load(modelPath, opt);
        const Deep2::TensorInfo* tq = lr.GetTensor("blk.0.attn_q.weight");
        if (tq && tq->data) {
            const size_t cols = 2048, bpr = 8;
            const BlockQ4K* blocks = reinterpret_cast<const BlockQ4K*>(tq->data);
            Deep2::QuantKernelRegistry::Instance().Initialize();
            auto kernel = Deep2::QuantKernelRegistry::Instance().GetGEMV((int)Deep2::GGMLType::GGML_TYPE_Q4_K);

            auto probeRow = [&](int row, FILE* f) {
                if (row < 0 || row >= (int)n) return;
                // FP64 dequant-dot per superblock
                const BlockQ4K* rowB = blocks + (size_t)row * bpr;
                double acc64 = 0;
                std::fprintf(f, "=== row=%d deep2_Q=%.9e llama_Q=%.9e abs=%.9e ===\n",
                             row, (double)d2[(size_t)row], (double)ll[(size_t)row],
                             std::fabs((double)d2[(size_t)row] - (double)ll[(size_t)row]));
                for (size_t b = 0; b < bpr; ++b) {
                    float tmp[256];
                    ggmlDequantBlock(rowB[b], tmp);
                    double gDot = 0;
                    for (size_t i = 0; i < 256; ++i)
                        gDot += (double)tmp[i] * (double)attn[b * 256 + i];
                    acc64 += gDot;
                    std::fprintf(f, "block=%zu fp64_dequant_dot=%.17g\n", b, gDot);
                }
                float yrow = 0.f;
                if (kernel) {
                    std::vector<float> y(2048, 0.f);
                    kernel((const uint8_t*)tq->data, attn.data(), y.data(), 2048, cols);
                    yrow = y[(size_t)row];
                }
                std::fprintf(f, "fp64_row_sum=%.17g prod_gemv_row=%.9e deep2_dump=%.9e llama_dump=%.9e\n",
                             acc64, (double)yrow, (double)d2[(size_t)row], (double)ll[(size_t)row]);
            };

            FILE* bd = std::fopen((std::string(outDir) + "\\row_block_dots.txt").c_str(), "w");
            if (bd) {
                std::fprintf(bd, "attn_norm_fnv=%016llx l2=%.9e\n",
                             (unsigned long long)fnv1a(attn.data(), attn.size()),
                             l2norm(attn.data(), attn.size()));
                probeRow(firstDiff, bd);
                if (largestIdx != firstDiff) probeRow(largestIdx, bd);
                // Also top-3 rows
                for (int r = 0; r < 3; ++r) probeRow(order[r], bd);
                std::fclose(bd);
            }
        }
    }

    if (vf) {
        std::fprintf(vf, "pattern_guess=%s\n", pattern);
        std::fprintf(vf, "fnv_match_llama=%s\n", fnvL == 0x8d53927ede5ddb3full ? "YES" : "NO");
        std::fprintf(vf, "fnv_match_deep2_cert=%s\n", fnvD == 0xced1abe971861249ull ? "YES" : "NO");
        std::fclose(vf);
    }

    FILE* verdict = std::fopen((std::string(outDir) + "\\verdict.txt").c_str(), "w");
    if (verdict) {
        std::fprintf(verdict,
            "BATCH2_Q_ELEMDIFF=%s\n"
            "deep2_fnv=%016llx\n"
            "llama_fnv=%016llx\n"
            "max_abs_error=%.17g\n"
            "mean_abs_error=%.17g\n"
            "rms_error=%.17g\n"
            "number_exact_equal=%zu\n"
            "number_bitwise_different=%zu\n"
            "first_different_index=%d\n"
            "largest_error_index=%d\n"
            "pattern_guess=%s\n"
            "authority=CPU llama Q_PRE_ROPE_0 dump\n"
            "next=inspect row_block_dots.txt for first/largest row\n",
            bitDiff == 0 ? "PASS" : "FAIL",
            (unsigned long long)fnvD, (unsigned long long)fnvL,
            maxAbs, meanAbs, rms, exact, bitDiff, firstDiff, largestIdx, pattern);
        std::fclose(verdict);
    }

    std::printf("pattern_guess=%s\n", pattern);
    return bitDiff == 0 ? 0 : 1;
}
