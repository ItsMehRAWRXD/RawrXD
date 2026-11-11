// logit_compare.cpp -- dependency-free independent parity comparator
// Replaces tools/gate5_independent_logits_compare.py (python/numpy unavailable).
// Usage: logit_compare.exe <refDir> <refPrefix> <d2Dir> <d2Prefix> <vocab>
//   e.g. logit_compare.exe REF ref_logits_pos D2G d2_logits_pos 32000
// Reads <dir>/<prefix><N>.bin as raw f32[vocab]; reports per-position
// argmax agreement, cosine, max-abs, RMSE vs the independent reference, and
// classifies disagreements as margin-explained (top-2 margin < max-abs) vs not.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static bool Load(const std::string& p, size_t vocab, std::vector<float>& v) {
    FILE* f = fopen(p.c_str(), "rb");
    if (!f) return false;
    v.resize(vocab);
    size_t n = fread(v.data(), sizeof(float), vocab, f);
    fclose(f);
    return n == vocab;
}

int main(int argc, char** argv) {
    if (argc < 6) {
        std::printf("usage: logit_compare.exe <refDir> <refPrefix> <d2Dir> <d2Prefix> <vocab>\n");
        return 1;
    }
    std::string refDir = argv[1], refPre = argv[2];
    std::string d2Dir = argv[3], d2Pre = argv[4];
    size_t vocab = (size_t)std::strtoull(argv[5], nullptr, 10);

    int agree = 0, total = 0, nonfinite = 0;
    long long bitdiff = 0;      // elements whose raw f32 bit pattern differs
    double worstCos = 1e9, worstAbs = 0.0, worstRmse = 0.0;
    int worstCosPos = -1, worstAbsPos = -1, worstRmsePos = -1;
    int firstMiss = -1;
    std::vector<int> explained, unexplained;
    for (size_t pos = 0;; ++pos) {
        std::string rp = refDir + "/" + refPre + std::to_string(pos) + ".bin";
        std::string dp = d2Dir + "/" + d2Pre + std::to_string(pos) + ".bin";
        // Stop at first missing ref (defines N).
        FILE* tf = fopen(rp.c_str(), "rb");
        if (!tf) break;
        fclose(tf);
        std::vector<float> r, d;
        if (!Load(rp, vocab, r)) { std::printf("FAIL load %s\n", rp.c_str()); return 2; }
        { FILE* df = fopen(dp.c_str(), "rb"); if (!df) break; fclose(df); }  // stop at d2 boundary
        if (!Load(dp, vocab, d)) { std::printf("FAIL load %s\n", dp.c_str()); return 2; }
        double dot = 0, nr = 0, nd = 0, maxabs = 0, sq = 0;
        size_t ar = 0, ad = 0;
        bool allFinite = true;
        for (size_t i = 0; i < vocab; ++i) {
            double a = r[i], b = d[i];
            uint32_t ba, bb; std::memcpy(&ba, &r[i], 4); std::memcpy(&bb, &d[i], 4);
            if (ba != bb) bitdiff++;
            if (!std::isfinite(b)) allFinite = false;
            dot += a * b; nr += a * a; nd += b * b;
            double df = std::fabs(a - b);
            if (df > maxabs) maxabs = df;
            sq += df * df;
            if (a > r[ar]) ar = i;
            if (b > d[ad]) ad = i;
        }
        if (!allFinite) nonfinite++;
        double cos = dot / (std::sqrt(nr) * std::sqrt(nd));
        double rmse = std::sqrt(sq / vocab);
        // top-2 margin of the reference
        double m1 = -1e30, m2 = -1e30;
        for (size_t i = 0; i < vocab; ++i) if (r[i] > m1) { m2 = m1; m1 = r[i]; } else if (r[i] > m2) m2 = r[i];
        double margin = m1 - m2;
        bool ok = (ar == ad);
        if (ok) agree++;
        else {
            if (firstMiss < 0) firstMiss = (int)pos;
            if (margin < maxabs) explained.push_back((int)pos); else unexplained.push_back((int)pos);
        }
        if (cos < worstCos) { worstCos = cos; worstCosPos = (int)pos; }
        if (maxabs > worstAbs) { worstAbs = maxabs; worstAbsPos = (int)pos; }
        if (rmse > worstRmse) { worstRmse = rmse; worstRmsePos = (int)pos; }
        total++;
    }
    std::printf("positions=%d vocab=%zu\n", total, vocab);
    if (total == 0) {
        std::printf("COMPARISON_INCONCLUSIVE: 0 positions compared (missing/empty ref or d2 tensor) - FAIL CLOSED\n");
        return 4;
    }
    std::printf("argmax_agreement=%d/%d\n", agree, total);
    std::printf("worst_cosine=%.8f (pos %d)\n", worstCos, worstCosPos);
    std::printf("worst_maxabs=%.6f (pos %d)\n", worstAbs, worstAbsPos);
    std::printf("worst_rmse=%.6f (pos %d)\n", worstRmse, worstRmsePos);
    std::printf("nonfinite_logits=%d\n", nonfinite);
    std::printf("bitwise_identical=%s (elements_ne=%lld / %lld)\n", bitdiff == 0 ? "YES" : "NO",
                bitdiff, (long long)total * (long long)vocab);
    std::printf("first_argmax_divergence=%s\n", firstMiss < 0 ? "none" : std::to_string(firstMiss).c_str());
    std::printf("disagreements=%d explained(margin<maxabs)=%d unexplained=%d\n",
                total - agree, (int)explained.size(), (int)unexplained.size());
    for (int p : explained) std::printf("  explained pos %d\n", p);
    for (int p : unexplained) std::printf("  UNEXPLAINED pos %d\n", p);
    return 0;
}
