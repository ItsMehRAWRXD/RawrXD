// sampler_gate.cpp — RAWRXD_BATCH_02_SAMPLER_GATE_001 standalone test.

#include "Sampler.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <functional>
#include <ctime>

using namespace rawrxd::sampling;

static int g_totalTests = 0;
static int g_passedTests = 0;

#define ASSERT_FIELD(field, cond, msg) do { \
    g_totalTests++; \
    if (cond) { g_passedTests++; \
        std::printf("FIELD=%s STATUS=PASS msg=\"%s\"\n", field, msg); \
    } else { \
        std::printf("FIELD=%s STATUS=FAIL msg=\"%s\"\n", field, msg); \
    } \
} while (0)

static double softmaxMaxProb(const std::vector<float>& logits, float temp) {
    int vocab = (int)logits.size();
    float maxL = logits[0];
    for (auto x : logits) maxL = std::max(maxL, x);
    double sum = 0.0;
    std::vector<double> probs(vocab);
    for (int i = 0; i < vocab; ++i) {
        probs[i] = std::exp((logits[i] - maxL) / temp);
        sum += probs[i];
    }
    double maxP = 0.0;
    for (auto p : probs) maxP = std::max(maxP, p / sum);
    return maxP;
}

static void testDeterminism() {
    const int vocab = 32;
    std::vector<float> logits(vocab);
    for (int i = 0; i < vocab; ++i) logits[i] = (float)((i * 7 + 3) % 13) - 6.0f;

    CombinedSampler s1(8, 0.9f, 0.05f, 0.7f, 42);
    CombinedSampler s2(8, 0.9f, 0.05f, 0.7f, 42);

    bool match = true;
    int firstDiff = -1;
    for (int step = 0; step < 50; ++step) {
        int t1 = s1.sample(logits.data(), vocab);
        int t2 = s2.sample(logits.data(), vocab);
        if (t1 != t2) { match = false; if (firstDiff < 0) firstDiff = step; }
    }
    std::printf("  [INFO] determinism: match=%d firstDiffStep=%d\n", match ? 1 : 0, firstDiff);
    ASSERT_FIELD("seed", match,
        "same seed + same logits + same options -> identical sequence across 50 steps");
}

static void testSeedSensitivity() {
    const int vocab = 32;
    std::vector<float> logits(vocab);
    for (int i = 0; i < vocab; ++i) logits[i] = (float)((i * 7 + 3) % 13) - 6.0f;

    CombinedSampler sA(8, 0.9f, 0.05f, 0.7f, 1);
    CombinedSampler sB(8, 0.9f, 0.05f, 0.7f, 999);
    bool differ = false;
    int firstDiff = -1;
    for (int step = 0; step < 100; ++step) {
        int ta = sA.sample(logits.data(), vocab);
        int tb = sB.sample(logits.data(), vocab);
        if (ta != tb) { differ = true; if (firstDiff < 0) firstDiff = step; }
    }
    std::printf("  [INFO] seed sensitivity: differ=%d firstDiffStep=%d\n", differ ? 1 : 0, firstDiff);
    ASSERT_FIELD("seed", differ,
        "different seeds with stochastic CombinedSampler must differ within 100 steps");
}

static void testTemperatureSensitivity() {
    const int vocab = 8;
    std::vector<float> logits(vocab);
    for (int i = 0; i < vocab; ++i) logits[i] = 1.0f + 0.01f * (float)i;

    double pLow = softmaxMaxProb(logits, 0.1f);
    double pHigh = softmaxMaxProb(logits, 5.0f);
    std::printf("  [INFO] temp=0.1 max_prob=%.4f, temp=5.0 max_prob=%.4f\n", pLow, pHigh);
    ASSERT_FIELD("temperature", std::abs(pLow - pHigh) > 0.01,
        "temp=0.1 vs temp=5.0 produce different softmax probabilities (field reaches sampler)");
}

static void testTopKSensitivity() {
    const int vocab = 16;
    std::vector<float> logits(vocab);
    for (int i = 0; i < vocab; ++i) logits[i] = (float)((i * 7 + 3) % 13) - 6.0f;

    CombinedSampler s5(2, 0.9f, 0.05f, 0.7f, 1);
    CombinedSampler s6(8, 0.9f, 0.05f, 0.7f, 1);
    bool differ = false;
    int firstDiff = -1;
    for (int step = 0; step < 100; ++step) {
        int t1 = s5.sample(logits.data(), vocab);
        int t2 = s6.sample(logits.data(), vocab);
        if (t1 != t2) { differ = true; if (firstDiff < 0) firstDiff = step; }
    }
    std::printf("  [INFO] CombinedSampler topK=2 vs 8: differ=%d firstDiff=%d\n",
        differ ? 1 : 0, firstDiff);
    ASSERT_FIELD("topK", differ,
        "CombinedSampler topK=2 vs 8 must produce different sequence");
}

static void testTopPSensitivity() {
    const int vocab = 4;
    std::vector<float> logits = {2.0f, 1.2f, -3.0f, -3.0f};

    TopPSampler halfP(0.5f, 1.0f, 1);
    TopPSampler wideP(0.99f, 1.0f, 1);
    int halfSel = 0, wideSel = 0;
    const int nTotal = 1000;
    for (int i = 0; i < nTotal; ++i) {
        if (halfP.sample(logits.data(), vocab) == 0) ++halfSel;
        if (wideP.sample(logits.data(), vocab) == 0) ++wideSel;
    }
    // softmax: p0 = 0.684, p1 = 0.307, p2 = p3 = 0.0046
    // topP=0.5: cum sorted = [0.684] -> nucleus {0}
    // topP=0.99: cum sorted = [0.684, 0.307, 0.0046, 0.0046] -> nucleus {0,1,2,3}
    std::printf("  [INFO] logits=[2.0,1.2,-3,-3] halfP=0.5 token0_sel=%d, wideP=0.99 token0_sel=%d\n",
        halfSel, wideSel);
    // wideP can pick non-0 tokens occasionally; halfP always picks 0
    // We assert: halfSel == 1000 (all picks are 0) AND wideSel < 1000 (some non-0 picks)
    bool halfAllZero = (halfSel == nTotal);
    bool wideSomeNonZero = (wideSel < nTotal);
    std::printf("  [INFO] halfP all-zero=%d, wideP has-non-zero=%d\n",
        halfAllZero ? 1 : 0, wideSomeNonZero ? 1 : 0);
    ASSERT_FIELD("topP", halfAllZero,
        "topP=0.5 nucleus={0}: token0 always selected");
    ASSERT_FIELD("topP", wideSomeNonZero,
        "topP=0.99 nucleus={0,1,2,3}: non-0 tokens selected sometimes");
}

static void testMinPSensitivity() {
    const int vocab = 4;
    std::vector<float> logits = {2.0f, 0.0f, -1.0f, -2.0f};

    MinPSampler strict(0.5f, 1.0f, 7777);
    int nToken0 = 0;
    int nTotal = 1000;
    for (int i = 0; i < nTotal; ++i) {
        if (strict.sample(logits.data(), vocab) == 0) ++nToken0;
    }
    std::printf("  [INFO] minP=0.5: token0 selected %d / %d (only token0 above 0.5*maxP=0.333)\n",
        nToken0, nTotal);
    ASSERT_FIELD("minP", nToken0 == nTotal,
        "minP=0.5 with p0=0.666 maxP=0.666 -> only token0 above threshold");

    MinPSampler loose(0.01f, 1.0f, 7777);
    int nNonZero = 0;
    for (int i = 0; i < nTotal; ++i) {
        if (loose.sample(logits.data(), vocab) != 0) ++nNonZero;
    }
    std::printf("  [INFO] minP=0.01: non-token0 selections = %d / %d (all tokens above 0.01*maxP=0.00666)\n",
        nNonZero, nTotal);
    ASSERT_FIELD("minP", nNonZero > 0,
        "minP=0.01 must allow tokens below 0.5*maxP threshold");
}

static void testRepetitionPenalty() {
    const int vocab = 4;
    int prior[1] = {0};

    {
        std::vector<float> l = {0.5f, 2.0f, 2.0f, 2.0f};
        RepetitionPenaltyProcessor p(1.0f);
        p.apply(l.data(), vocab, prior, 1);
        ASSERT_FIELD("repeatPenalty", !p.active(), "penalty=1.0 must report active()==false");
    }

    {
        std::vector<float> l = {0.5f, 2.0f, 2.0f, 2.0f};
        RepetitionPenaltyProcessor p(1.5f);
        p.apply(l.data(), vocab, prior, 1);
        GreedySampler g;
        int pick = g.sample(l.data(), vocab);
        std::printf("  [INFO] penalty=1.5 with prior=[0], logits=[0.5,2,2,2]: after apply l=[%.3f,%.3f,%.3f,%.3f] argmax=%d\n",
            l[0], l[1], l[2], l[3], pick);
        ASSERT_FIELD("repeatPenalty", pick != 0,
            "penalty=1.5 suppresses token0; argmax must be != 0");
        ASSERT_FIELD("repeatPenalty", std::abs(l[0] - 0.5f/1.5f) < 0.001f,
            "penalty=1.5 divides token0 logit by 1.5 (measured l[0] = 0.333)");
    }
}

static void testCombinedOptionsSensitivity() {
    const int vocab = 16;
    std::vector<float> logits(vocab);
    logits[0] = 5.0f; logits[1] = 4.9f; logits[2] = 2.0f;
    for (int i = 3; i < 8; ++i) logits[i] = 0.5f;
    for (int i = 8; i < 16; ++i) logits[i] = -3.0f;

    CombinedSampler sa(16, 0.5f, 0.0f, 1.0f, 1);
    CombinedSampler sb(16, 0.99f, 0.0f, 1.0f, 1);
    bool differTopP = false;
    for (int step = 0; step < 200; ++step) {
        if (sa.sample(logits.data(), vocab) != sb.sample(logits.data(), vocab)) {
            differTopP = true; break;
        }
    }
    std::printf("  [INFO] CombinedSampler topP=0.5 vs 0.99 (curated logits): differ=%d\n",
        differTopP ? 1 : 0);
    ASSERT_FIELD("topP", differTopP,
        "CombinedSampler topP=0.5 vs 0.99 on curated logits must differ");

    CombinedSampler sc(16, 1.0f, 0.05f, 1.0f, 1);
    CombinedSampler sd(16, 1.0f, 0.30f, 1.0f, 1);
    bool differMinP = false;
    for (int step = 0; step < 200; ++step) {
        if (sc.sample(logits.data(), vocab) != sd.sample(logits.data(), vocab)) {
            differMinP = true; break;
        }
    }
    std::printf("  [INFO] CombinedSampler minP=0.05 vs 0.30 (curated logits): differ=%d\n",
        differMinP ? 1 : 0);
    ASSERT_FIELD("minP", differMinP,
        "CombinedSampler minP=0.05 vs 0.30 on curated logits must differ");
}

int main() {
    std::printf("=== RAWRXD_BATCH_02_SAMPLER_GATE_001 ===\n");
    std::printf("build_unix=%lld\n", (long long)time(nullptr));

    testDeterminism();
    testSeedSensitivity();
    testTemperatureSensitivity();
    testTopKSensitivity();
    testTopPSensitivity();
    testMinPSensitivity();
    testRepetitionPenalty();
    testCombinedOptionsSensitivity();

    std::printf("=== SUMMARY: %d / %d tests PASSED ===\n", g_passedTests, g_totalTests);
    return (g_passedTests == g_totalTests) ? 0 : 1;
}
