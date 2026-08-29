/*
 * test_q_elemdiff_standalone.cpp — pure float compare + optional GGUF block-dot
 * No InferenceEngine link (avoids rebuild races).
 */
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

static bool loadF32(const char* path, std::vector<float>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz < 4 || (sz % 4) != 0) { std::fclose(f); return false; }
    out.resize((size_t)sz / 4);
    size_t n = std::fread(out.data(), 1, (size_t)sz, f);
    std::fclose(f);
    return n == (size_t)sz;
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

struct BlockQ4K {
    uint16_t d, dmin;
    uint8_t scales[12];
    uint8_t qs[128];
};

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
    float r; std::memcpy(&r, &f, 4); return r;
}

static void ggmlGetScaleMinK4(int j, const uint8_t* q, uint8_t* d, uint8_t* m) {
    if (j < 4) { *d = q[j] & 63; *m = q[j + 4] & 63; }
    else {
        *d = (q[j + 4] & 0xF) | ((q[j - 4] >> 6) << 4);
        *m = (q[j + 4] >> 4) | ((q[j - 0] >> 6) << 4);
    }
}

static void ggmlDequantBlock(const BlockQ4K& blk, float* y) {
    const uint8_t* q = blk.qs;
    const float d = fp16ToF32(blk.d);
    const float minv = fp16ToF32(blk.dmin);
    int is = 0; uint8_t sc, m;
    for (int j = 0; j < 256; j += 64) {
        ggmlGetScaleMinK4(is + 0, blk.scales, &sc, &m);
        const float d1 = d * sc, m1 = minv * m;
        ggmlGetScaleMinK4(is + 1, blk.scales, &sc, &m);
        const float d2 = d * sc, m2 = minv * m;
        for (int l = 0; l < 32; ++l) *y++ = d1 * (float)(q[l] & 0xF) - m1;
        for (int l = 0; l < 32; ++l) *y++ = d2 * (float)(q[l] >> 4) - m2;
        q += 32; is += 2;
    }
}

// Minimal GGUF tensor seek for blk.0.attn_q.weight (Q4_K)
static bool loadAttnQBlocks(const char* ggufPath, std::vector<uint8_t>& bytes, size_t expectRows = 2048) {
    FILE* f = std::fopen(ggufPath, "rb");
    if (!f) return false;
    // Prefer frozen raw blocks from prior harness if present
    (void)expectRows;
    std::fclose(f);
    return false; // filled by caller via raw bin
}

int main(int argc, char** argv) {
    const char* deep2Path = argc > 1 ? argv[1] : nullptr;
    const char* llamaPath = argc > 2 ? argv[2] : nullptr;
    const char* attnPath  = argc > 3 ? argv[3] : nullptr;
    const char* attnQRaw  = argc > 4 ? argv[4] : nullptr; // optional attn_q_raw_blocks.bin
    const char* outDir    = argc > 5 ? argv[5]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_Q_ELEMDIFF)";
    if (!deep2Path || !llamaPath) {
        std::fprintf(stderr, "usage: deep2_Q.bin llama_Q.bin [attn_norm.bin] [attn_q_raw_blocks.bin] [out_dir]\n");
        return 2;
    }
    MKDIR(outDir);

    std::vector<float> d2, ll, attn;
    if (!loadF32(deep2Path, d2) || !loadF32(llamaPath, ll)) {
        std::fprintf(stderr, "LOAD_FAIL\n");
        return 3;
    }
    if (d2.size() != ll.size()) {
        std::fprintf(stderr, "SIZE_MISMATCH %zu vs %zu\n", d2.size(), ll.size());
        return 3;
    }
    const size_t n = d2.size();
    const uint64_t fnvD = fnv1a(d2.data(), n);
    const uint64_t fnvL = fnv1a(ll.data(), n);

    double maxAbs = 0, sumAbs = 0, sumSq = 0;
    size_t exact = 0, bitDiff = 0;
    int firstDiff = -1, largestIdx = -1;
    size_t buck1e10 = 0, buck1e8 = 0, buck1e6 = 0, buck1e4 = 0, buckBig = 0;
    std::vector<size_t> diffPer32(32, 0), diffPer256(256, 0);
    std::vector<size_t> diffPerRow; // if n==2048, each index is a Q output row

    for (size_t i = 0; i < n; ++i) {
        uint32_t bd = 0, bl = 0;
        std::memcpy(&bd, &d2[i], 4);
        std::memcpy(&bl, &ll[i], 4);
        if (bd == bl) { ++exact; continue; }
        ++bitDiff;
        if (firstDiff < 0) firstDiff = (int)i;
        const double e = std::fabs((double)d2[i] - (double)ll[i]);
        sumAbs += e; sumSq += e * e;
        if (e > maxAbs) { maxAbs = e; largestIdx = (int)i; }
        if (e < 1e-10) ++buck1e10;
        else if (e < 1e-8) ++buck1e8;
        else if (e < 1e-6) ++buck1e6;
        else if (e < 1e-4) ++buck1e4;
        else ++buckBig;
        diffPer32[i % 32]++;
        diffPer256[i % 256]++;
    }
    // recount sumAbs including zeros for mean
    sumAbs = 0; sumSq = 0; maxAbs = 0; largestIdx = -1;
    for (size_t i = 0; i < n; ++i) {
        const double e = std::fabs((double)d2[i] - (double)ll[i]);
        sumAbs += e; sumSq += e * e;
        if (e > maxAbs) { maxAbs = e; largestIdx = (int)i; }
    }
    const double meanAbs = sumAbs / (double)n;
    const double rms = std::sqrt(sumSq / (double)n);

    auto emit = [&](FILE* f) {
        std::fprintf(f, "n=%zu\n", n);
        std::fprintf(f, "deep2_fnv=%016llx l2=%.9e\n", (unsigned long long)fnvD, l2norm(d2.data(), n));
        std::fprintf(f, "llama_fnv=%016llx l2=%.9e\n", (unsigned long long)fnvL, l2norm(ll.data(), n));
        std::fprintf(f, "max_abs_error=%.17g\n", maxAbs);
        std::fprintf(f, "mean_abs_error=%.17g\n", meanAbs);
        std::fprintf(f, "rms_error=%.17g\n", rms);
        std::fprintf(f, "number_exact_equal=%zu\n", exact);
        std::fprintf(f, "number_bitwise_different=%zu\n", bitDiff);
        std::fprintf(f, "first_different_index=%d\n", firstDiff);
        std::fprintf(f, "largest_error_index=%d\n", largestIdx);
        if (firstDiff >= 0) {
            std::fprintf(f, "first_diff deep2=%.9e llama=%.9e abs=%.9e bits_d=0x%08x bits_l=0x%08x\n",
                (double)d2[(size_t)firstDiff], (double)ll[(size_t)firstDiff],
                std::fabs((double)d2[(size_t)firstDiff] - (double)ll[(size_t)firstDiff]),
                *(uint32_t*)&d2[(size_t)firstDiff], *(uint32_t*)&ll[(size_t)firstDiff]);
        }
        if (largestIdx >= 0) {
            std::fprintf(f, "largest_diff deep2=%.9e llama=%.9e abs=%.9e bits_d=0x%08x bits_l=0x%08x\n",
                (double)d2[(size_t)largestIdx], (double)ll[(size_t)largestIdx],
                std::fabs((double)d2[(size_t)largestIdx] - (double)ll[(size_t)largestIdx]),
                *(uint32_t*)&d2[(size_t)largestIdx], *(uint32_t*)&ll[(size_t)largestIdx]);
        }
        std::fprintf(f, "error_buckets exact=%zu lt1e-10=%zu lt1e-8=%zu lt1e-6=%zu lt1e-4=%zu ge1e-4=%zu\n",
                     exact, buck1e10, buck1e8, buck1e6, buck1e4, buckBig);
        std::fprintf(f, "diff_mod32:");
        for (size_t i = 0; i < 32; ++i) std::fprintf(f, " %zu", diffPer32[i]);
        std::fprintf(f, "\n");
        // ULP distance distribution for bitwise diffs
        size_t ulp1 = 0, ulp2_8 = 0, ulp9p = 0;
        for (size_t i = 0; i < n; ++i) {
            uint32_t bd = 0, bl = 0;
            std::memcpy(&bd, &d2[i], 4);
            std::memcpy(&bl, &ll[i], 4);
            if (bd == bl) continue;
            // signed-magnitude ulp distance for same-sign floats
            int32_t id = (int32_t)bd, il = (int32_t)bl;
            if (id < 0) id = 0x80000000 - id;
            if (il < 0) il = 0x80000000 - il;
            uint32_t ulp = (uint32_t)std::abs((int64_t)id - (int64_t)il);
            if (ulp <= 1) ++ulp1;
            else if (ulp <= 8) ++ulp2_8;
            else ++ulp9p;
        }
        std::fprintf(f, "ulp_buckets ulp1=%zu ulp2_8=%zu ulp9plus=%zu\n", ulp1, ulp2_8, ulp9p);
    };

    emit(stdout);
    FILE* sf = std::fopen((std::string(outDir) + "\\elemdiff_stats.txt").c_str(), "w");
    if (sf) { emit(sf); std::fclose(sf); }

    std::vector<int> order((int)n);
    for (int i = 0; i < (int)n; ++i) order[i] = i;
    std::sort(order.begin(), order.end(), [&](int a, int b) {
        return std::fabs((double)d2[(size_t)a] - (double)ll[(size_t)a]) >
               std::fabs((double)d2[(size_t)b] - (double)ll[(size_t)b]);
    });
    FILE* top = std::fopen((std::string(outDir) + "\\elemdiff_top20.txt").c_str(), "w");
    if (top) {
        std::fprintf(top, "rank index deep2 llama abs_err ulp\n");
        for (int r = 0; r < 20 && r < (int)n; ++r) {
            int i = order[r];
            double e = std::fabs((double)d2[(size_t)i] - (double)ll[(size_t)i]);
            uint32_t bd = 0, bl = 0;
            std::memcpy(&bd, &d2[(size_t)i], 4);
            std::memcpy(&bl, &ll[(size_t)i], 4);
            int32_t id = (int32_t)bd, il = (int32_t)bl;
            if (id < 0) id = 0x80000000 - id;
            if (il < 0) il = 0x80000000 - il;
            uint32_t ulp = (uint32_t)std::abs((int64_t)id - (int64_t)il);
            std::fprintf(top, "%d %d %.9e %.9e %.9e %u\n", r, i,
                         (double)d2[(size_t)i], (double)ll[(size_t)i], e, ulp);
        }
        std::fclose(top);
    }

    const char* pattern = "unknown";
    if (bitDiff == 0) pattern = "IDENTICAL";
    else if (buckBig == 0 && buck1e4 == 0) pattern = "many_tiny_fp_diffs";
    else if (buckBig > 0 && buckBig < 16) pattern = "few_isolated_large";
    else if (buckBig > 100) pattern = "many_large_or_structured";
    else pattern = "mixed";

    // Block-dot using frozen attn_q raw blocks + ATTN_NORM
    if (attnPath && attnQRaw && loadF32(attnPath, attn) && attn.size() == 2048) {
        FILE* rf = std::fopen(attnQRaw, "rb");
        if (rf) {
            std::fseek(rf, 0, SEEK_END);
            long sz = std::ftell(rf);
            std::fseek(rf, 0, SEEK_SET);
            std::vector<uint8_t> raw((size_t)sz);
            std::fread(raw.data(), 1, (size_t)sz, rf);
            std::fclose(rf);
            const size_t bpr = 8;
            const size_t rowBytes = bpr * 144;
            const BlockQ4K* blocks = reinterpret_cast<const BlockQ4K*>(raw.data());
            FILE* bd = std::fopen((std::string(outDir) + "\\row_block_dots.txt").c_str(), "w");
            if (bd) {
                std::fprintf(bd, "attn_norm_fnv=%016llx l2=%.9e\n",
                             (unsigned long long)fnv1a(attn.data(), attn.size()),
                             l2norm(attn.data(), attn.size()));
                auto probe = [&](int row) {
                    if (row < 0 || (size_t)row >= n) return;
                    if ((size_t)row * rowBytes + rowBytes > raw.size()) return;
                    const BlockQ4K* rowB = blocks + (size_t)row * bpr;
                    double acc64 = 0;
                    std::fprintf(bd, "=== row=%d deep2=%.9e llama=%.9e abs=%.9e ===\n",
                                 row, (double)d2[(size_t)row], (double)ll[(size_t)row],
                                 std::fabs((double)d2[(size_t)row] - (double)ll[(size_t)row]));
                    for (size_t b = 0; b < bpr; ++b) {
                        float tmp[256];
                        ggmlDequantBlock(rowB[b], tmp);
                        double gDot = 0;
                        for (size_t i = 0; i < 256; ++i)
                            gDot += (double)tmp[i] * (double)attn[b * 256 + i];
                        acc64 += gDot;
                        std::fprintf(bd, "block=%zu fp64_dequant_dot=%.17g\n", b, gDot);
                    }
                    std::fprintf(bd, "fp64_row_sum=%.17g deep2_dump=%.9e llama_dump=%.9e "
                                 "delta_d2=%.9e delta_ll=%.9e\n",
                                 acc64, (double)d2[(size_t)row], (double)ll[(size_t)row],
                                 std::fabs(acc64 - (double)d2[(size_t)row]),
                                 std::fabs(acc64 - (double)ll[(size_t)row]));
                };
                probe(firstDiff);
                if (largestIdx != firstDiff) probe(largestIdx);
                for (int r = 0; r < 5; ++r) probe(order[r]);
                std::fclose(bd);
            }
        }
    }
    (void)loadAttnQBlocks;

    FILE* vf = std::fopen((std::string(outDir) + "\\verdict.txt").c_str(), "w");
    if (vf) {
        std::fprintf(vf,
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
            "authority_files=deep2_Q_PRE_ROPE_0_pos0.bin,llama_Q_PRE_ROPE_0_pos0.bin\n"
            "discriminator=%s\n",
            bitDiff == 0 ? "PASS" : "FAIL",
            (unsigned long long)fnvD, (unsigned long long)fnvL,
            maxAbs, meanAbs, rms, exact, bitDiff, firstDiff, largestIdx, pattern,
            (buckBig == 0 && buck1e4 == 0)
                ? "many_tiny_diffs => accumulation/FP precision"
                : (buckBig > 0 && buckBig < 16)
                    ? "few_isolated => row stride/addressing"
                    : "inspect top20 + block dots");
        std::fclose(vf);
    }
    std::printf("pattern_guess=%s\n", pattern);
    return bitDiff == 0 ? 0 : 1;
}
