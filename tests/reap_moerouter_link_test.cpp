// ============================================================================
// reap_moerouter_link_test.cpp — Exercises the REAL Deep2::MoERouter class
// (not just the core) to prove the production single-file routing path applies
// sigmoid gating + selection-only correction bias correctly.
//
// Each invariant is verified independently against the sigmoid reference:
//   s0 = sigmoid(0)  = 0.5
//   s1 = sigmoid(10) = 0.9999546
//   w0 = s0/(s0+s1)  = 0.33334339
//   w1 = s1/(s0+s1)  = 0.66665661
// The correction bias changes SELECTION only, never the activated weights.
//
// Links: MoERouter.cpp + ReapPhysicalBank.cpp. No other dependencies.
// ============================================================================
#include "MoERouter.hpp"

#include <cmath>
#include <cstdio>
#include <vector>

using namespace Deep2;

static int g_fails = 0;
static void check(bool c, const char* w) {
    if (!c) { ++g_fails; std::fprintf(stderr, "FAIL: %s\n", w); }
    else std::fprintf(stdout, "PASS: %s\n", w);
}
static bool approx(float a, float b, float e = 1e-4f) { return std::fabs(a - b) <= e; }

// Reference sigmoid, independent of the code under test.
static float refSigmoid(float x) { return 1.0f / (1.0f + std::exp(-x)); }

int main() {
    const float s0 = refSigmoid(0.0f);   // 0.5
    const float s1 = refSigmoid(10.0f);  // ~0.9999546

    // 4 experts, hiddenDim 2. Experts 1 and 3 read hidden[1].
    MoEConfig cfg;
    cfg.numExperts = 4;
    cfg.numActiveExperts = 2;
    cfg.hiddenDim = 2;
    cfg.scoringFunc = 1;          // sigmoid
    cfg.normTopkProb = true;
    cfg.routedScalingFactor = 1.0f;

    MoERouter router;
    router.Initialize(cfg);

    // Row-major [numExperts, hiddenDim].
    std::vector<float> w = {
        0.f, 0.f,   // expert 0 -> logit 0
        0.f, 10.f,  // expert 1 -> logit 10 (hidden[1]=1)
        0.f, 0.f,   // expert 2 -> logit 0
        0.f, 10.f,  // expert 3 -> logit 10
    };
    router.SetRouterWeights(w.data(), 4, 2);

    std::vector<float> hidden = {0.f, 1.f};

    // --- Control A: no bias. Selection and ordering. ---
    TokenRoute r = router.Route(hidden.data());
    check(r.topExperts.size() == 2, "A: two experts selected");
    check(r.topExperts[0].expertId == 1 && r.topExperts[1].expertId == 3,
          "A: selection picks highest-logit experts (1,3)");
    // Activated-score invariants (unbiased, pre-normalization).
    check(approx(r.routerLogits[1], 10.0f) && approx(r.routerLogits[3], 10.0f),
          "A: router logits = W.x (10 for experts 1,3)");
    // Both selected experts (1 and 3) have activated score s1=sigmoid(10), so
    // after normalization each weight is s1/(s1+s1) = 0.5.
    check(approx(r.topExperts[0].weight, 0.5f, 1e-3f),
          "A: expert 1 normalized weight = 0.5");
    check(approx(r.topExperts[1].weight, 0.5f, 1e-3f),
          "A: expert 3 normalized weight = 0.5");
    check(approx(r.topExperts[0].weight + r.topExperts[1].weight, 1.0f, 1e-4f),
          "A: normalized weights sum to one");

    // --- Control B: bias changes SELECTION only, not weights. ---
    MoEConfig cfg2 = cfg;
    MoERouter router2;
    router2.Initialize(cfg2);
    router2.SetRouterWeights(w.data(), 4, 2);
    std::vector<float> bias = {5.f, 0.f, 0.f, 0.f};  // expert 0 choice dominates
    router2.SetCorrectionBias(bias.data(), 4);
    TokenRoute r2 = router2.Route(hidden.data());
    check(r2.topExperts[0].expertId == 0,
          "B: correction bias changes SELECTION (expert 0 first)");
    // Expert 0 has logit 0 -> activated s0=0.5. Expert 1 (next choice) has s1.
    float w0Norm = s0 / (s0 + s1);
    check(approx(r2.topExperts[0].weight, w0Norm, 1e-3f),
          "B: expert 0 weight = s0/(s0+s1) from UNBIASED activation");
    float sumB = 0.f;
    for (auto& e : r2.topExperts) sumB += e.weight;
    check(approx(sumB, 1.0f, 1e-4f), "B: weights sum to one despite bias");
    // Bias must not appear anywhere in the weight.
    check(r2.topExperts[0].weight < 0.5f,
          "B: expert 0 weight < 0.5 (bias 5.0 did not leak)");

    std::fprintf(stdout, "=== MoERouter link test: %s ===\n", g_fails == 0 ? "PASS" : "FAIL");
    return g_fails == 0 ? 0 : 1;
}