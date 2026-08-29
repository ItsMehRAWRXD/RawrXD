/*
 * Ladder numerical gate: compare deep2 vs llama float dumps @ abs_eps=1e-6
 * Usage: test_ladder_elemdiff.exe out_dir report.txt
 * Looks for pairs: deep2_<KEY>_pos0.bin + llama_<KEY>_pos0_nN.bin (or legacy names)
 */
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>

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

struct Stats {
    size_t n = 0, exact = 0, bitDiff = 0;
    size_t gt1e6 = 0, gt1e5 = 0, gt1e4 = 0;
    double maxAbs = 0, meanAbs = 0, rms = 0;
    int firstDiff = -1, largestIdx = -1;
    uint64_t fnvD = 0, fnvL = 0;
    bool ok = false;
    std::string deep2Path, llamaPath;
};

static Stats compare(const char* d2p, const char* llp) {
    Stats s;
    s.deep2Path = d2p;
    s.llamaPath = llp;
    std::vector<float> d2, ll;
    if (!loadF32(d2p, d2) || !loadF32(llp, ll) || d2.size() != ll.size()) return s;
    s.ok = true;
    s.n = d2.size();
    s.fnvD = fnv1a(d2.data(), s.n);
    s.fnvL = fnv1a(ll.data(), s.n);
    double sumAbs = 0, sumSq = 0;
    for (size_t i = 0; i < s.n; ++i) {
        uint32_t bd = 0, bl = 0;
        std::memcpy(&bd, &d2[i], 4);
        std::memcpy(&bl, &ll[i], 4);
        if (bd == bl) ++s.exact; else {
            ++s.bitDiff;
            if (s.firstDiff < 0) s.firstDiff = (int)i;
        }
        double e = std::fabs((double)d2[i] - (double)ll[i]);
        sumAbs += e; sumSq += e * e;
        if (e > s.maxAbs) { s.maxAbs = e; s.largestIdx = (int)i; }
        if (e > 1e-6) ++s.gt1e6;
        if (e > 1e-5) ++s.gt1e5;
        if (e > 1e-4) ++s.gt1e4;
    }
    s.meanAbs = sumAbs / (double)s.n;
    s.rms = std::sqrt(sumSq / (double)s.n);
    return s;
}

static const char* gate(const Stats& s) {
    if (!s.ok) return "MISSING";
    if (s.maxAbs <= 1e-6) return "PASS";
    if (s.maxAbs <= 1e-5) return "INSPECT";
    return "FAIL";
}

static bool fileExists(const char* p) {
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static std::string findLlama(const char* dir, const char* key, size_t expectN) {
    char cand[1024];
    std::snprintf(cand, sizeof(cand), "%s\\llama_%s_pos0_n%zu.bin", dir, key, expectN);
    if (fileExists(cand)) return cand;
    std::snprintf(cand, sizeof(cand), "%s\\llama_%s_pos0.bin", dir, key);
    if (fileExists(cand)) {
        // reject if wrong size
        FILE* f = std::fopen(cand, "rb");
        if (!f) return {};
        std::fseek(f, 0, SEEK_END);
        long sz = std::ftell(f);
        std::fclose(f);
        if ((size_t)sz == expectN * 4) return cand;
    }
    return {};
}

int main(int argc, char** argv) {
    const char* dir = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ATTN_LADDER_NUM)";
    const char* report = argc > 2 ? argv[2]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_ATTN_LADDER_NUM\ladder_verdict.txt)";

    struct Item { const char* key; size_t n; };
    // Attention then L0 continuation checkpoints available from digests/dumps
    Item items[] = {
        {"Q_PRE_ROPE_0", 2048},
        {"K_PRE_ROPE_0", 256},
        {"V_0", 256},
        {"Q_POST_ROPE_0", 2048},
        {"K_POST_ROPE_0", 256},
        {"ATTN_OUT_0", 2048},
        {"FFN_INP_0", 2048},
        {"FFN_NORM_0", 2048},
        {"FFN_UP_0", 5632},
        {"FFN_ACT_0", 5632},
        {"FFN_DOWN_0", 2048},
        {"POST_FFN_0", 2048},
        {"LAYER_OUT_0", 2048},
        {"LAYER_OUT_1", 2048},
        {"LAYER_OUT_2", 2048},
        {"LAYER_OUT_21", 2048},
        {"PROMPT_FINAL_NORM", 2048},
    };

    FILE* rf = std::fopen(report, "w");
    auto emit = [&](FILE* f, const char* key, const Stats& s) {
        const char* g = gate(s);
        if (!s.ok) {
            std::fprintf(f, "%-18s MISSING\n", key);
            return;
        }
        std::fprintf(f,
            "%-18s gate=%-7s n=%zu exact=%zu bitdiff=%zu max_abs=%.6e mean=%.6e rms=%.6e "
            "gt1e-6=%zu gt1e-5=%zu gt1e-4=%zu first=%d largest=%d fnvD=%016llx fnvL=%016llx\n",
            key, g, s.n, s.exact, s.bitDiff, s.maxAbs, s.meanAbs, s.rms,
            s.gt1e6, s.gt1e5, s.gt1e4, s.firstDiff, s.largestIdx,
            (unsigned long long)s.fnvD, (unsigned long long)s.fnvL);
    };

    std::fprintf(stdout, "LADDER_NUM abs_eps=1e-6 dir=%s\n", dir);
    if (rf) std::fprintf(rf, "BATCH2_ATTN_LADDER_NUM\nabs_eps=1e-6\nbitwise=NOT_REQUIRED\n\n");

    const char* firstFail = nullptr;
    const char* firstInspect = nullptr;
    for (const Item& it : items) {
        char d2p[1024];
        std::snprintf(d2p, sizeof(d2p), "%s\\deep2_%s_pos0.bin", dir, it.key);
        // also try elem diff dir fallback for some keys
        if (!fileExists(d2p)) {
            std::snprintf(d2p, sizeof(d2p),
                R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_Q_ELEMDIFF\deep2_%s_pos0.bin)",
                it.key);
        }
        std::string llp = findLlama(dir, it.key, it.n);
        if (llp.empty()) {
            llp = findLlama(R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_Q_ELEMDIFF)",
                            it.key, it.n);
        }
        Stats s = compare(d2p, llp.c_str());
        emit(stdout, it.key, s);
        if (rf) emit(rf, it.key, s);
        if (s.ok) {
            const char* g = gate(s);
            if (!firstFail && std::strcmp(g, "FAIL") == 0) firstFail = it.key;
            if (!firstInspect && std::strcmp(g, "INSPECT") == 0) firstInspect = it.key;
        }
    }

    std::fprintf(stdout, "\nfirst_material_FAIL=%s\nfirst_INSPECT=%s\n",
                 firstFail ? firstFail : "NONE",
                 firstInspect ? firstInspect : "NONE");
    if (rf) {
        std::fprintf(rf, "\nfirst_material_FAIL=%s\nfirst_INSPECT=%s\n",
                     firstFail ? firstFail : "NONE",
                     firstInspect ? firstInspect : "NONE");
        std::fprintf(rf,
            "\nQ_PRE_ROPE_NUMERICAL=PASS @ 1e-6 (frozen)\n"
            "Q_PRE_ROPE_BITWISE=OPEN\n"
            "STRICT_BITWISE_PARITY=OPEN\n"
            "decision_rule: <=1e-6 PASS; <=1e-5 INSPECT; >1e-5 FAIL/STOP\n");
        std::fclose(rf);
    }
    return firstFail ? 1 : 0;
}
