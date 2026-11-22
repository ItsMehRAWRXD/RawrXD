// ============================================================================
// reap_moe_routing_core_test.cpp — Standalone native regression for the single
// metadata-driven MoE routing core (src/deep2/MoERoutingCore.hpp).
//
// No external dependencies. No stubs. Hand-computed reference values.
// Build:  g++ -std=c++17 -O2 -Wall -Wextra MoERoutingCore.hpp ... this file
// Exit code 0 iff every control passes.
// ============================================================================
#include "MoERoutingCore.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace Deep2::moe;

static int g_checks = 0;
static int g_fails = 0;

static void check(bool cond, const std::string& what) {
    ++g_checks;
    if (!cond) {
        ++g_fails;
        std::fprintf(stderr, "FAIL: %s\n", what.c_str());
    } else {
        std::fprintf(stdout, "PASS: %s\n", what.c_str());
    }
}

static bool approx(float a, float b, float eps = 1e-4f) {
    return std::fabs(a - b) <= eps;
}

static bool approxVec(const std::vector<float>& a, const std::vector<float>& b, float eps = 1e-4f) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (!approx(a[i], b[i], eps)) return false;
    return true;
}

static bool idsEqual(const std::vector<int>& a, const std::vector<int>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (a[i] != b[i]) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Control 1: Softmax routing, top-2, normalized.
//   logits = [1,2,3]; softmax = [0.0900,0.2447,0.6652]; top2 ids [2,1];
//   normalized weights [0.7311, 0.2689].
// ---------------------------------------------------------------------------
static void testSoftmaxBasic() {
    std::vector<float> logits = {1.f, 2.f, 3.f};
    RoutingParams p;
    p.scoring = ScoringFunc::Softmax;
    p.topK = 2;
    p.normTopkProb = true;
    p.routedScalingFactor = 1.0f;
    RoutingResult r = Route(logits.data(), 3, p);
    check(idsEqual(r.expertIds, {2, 1}), "softmax basic: ids [2,1]");
    std::vector<float> expect = {0.7311f, 0.2689f};
    check(approxVec(r.weights, expect), "softmax basic: normalized weights");
    check(approx(r.weights[0] + r.weights[1], 1.0f), "softmax basic: weights sum to 1");
}

// ---------------------------------------------------------------------------
// Control 2: Sigmoid routing with selection-only correction bias.
//   logits all 0 -> sigmoid 0.5. bias = [0,0,0.1,0]. choice=[.5,.5,.6,.5].
//   top2 ids [2,0]; weights UNBIASED [0.5,0.5] (bias never leaks).
// ---------------------------------------------------------------------------
static void testSigmoidBiasSelectionOnly() {
    std::vector<float> logits = {0.f, 0.f, 0.f, 0.f};
    std::vector<float> bias = {0.f, 0.f, 0.1f, 0.f};
    RoutingParams p;
    p.scoring = ScoringFunc::Sigmoid;
    p.topK = 2;
    p.hasCorrectionBias = true;
    p.correctionBias = bias.data();
    p.normTopkProb = true;
    p.routedScalingFactor = 1.0f;
    RoutingResult r = Route(logits.data(), 4, p);
    check(idsEqual(r.expertIds, {2, 0}), "sigmoid+bias: selection uses s+b (ids [2,0])");
    // Unbiased sigmoid scores are 0.5 for both; normalized -> [0.5,0.5].
    check(approxVec(r.weights, {0.5f, 0.5f}), "sigmoid+bias: weights are unbiased (0.5,0.5)");
    // Confirm the activated scores themselves are exactly sigmoid(0)=0.5.
    check(approx(r.scores[2], 0.5f) && approx(r.scores[0], 0.5f), "sigmoid: scores are sigmoid(logit)");
}

// ---------------------------------------------------------------------------
// Control 3: Group-limited routing.
//   8 experts, nGroup=2 (perGroup=4), topkGroup=1. bias bumps group 1.
//   Only experts 4..7 eligible; top2 ids [7,4].
// ---------------------------------------------------------------------------
static void testGroupLimited() {
    std::vector<float> logits(8, 0.f);  // sigmoid -> 0.5 everywhere
    std::vector<float> bias(8, 0.f);
    bias[7] = 1.0f;  // group 1 dominates
    RoutingParams p;
    p.scoring = ScoringFunc::Sigmoid;
    p.topK = 2;
    p.nGroup = 2;
    p.topkGroup = 1;
    p.hasCorrectionBias = true;
    p.correctionBias = bias.data();
    p.normTopkProb = true;
    p.routedScalingFactor = 1.0f;
    RoutingResult r = Route(logits.data(), 8, p);
    check(r.groupLimited, "group: group limiting engaged");
    check(idsEqual(r.expertIds, {7, 4}), "group: only top group eligible (ids [7,4])");
    for (int id : r.expertIds) check(id >= 4 && id < 8, "group: selected ids within winning group");
}

// ---------------------------------------------------------------------------
// Control 4: Routed scaling factor.
//   sigmoid 0.5 x2 normalized then x2.0 -> [1.0,1.0], sum = scaling.
// ---------------------------------------------------------------------------
static void testRoutedScaling() {
    std::vector<float> logits = {0.f, 0.f};
    RoutingParams p;
    p.scoring = ScoringFunc::Sigmoid;
    p.topK = 2;
    p.normTopkProb = true;
    p.routedScalingFactor = 2.0f;
    RoutingResult r = Route(logits.data(), 2, p);
    check(approxVec(r.weights, {1.0f, 1.0f}), "routed scaling: weights scaled to sum=2.0");
    check(approx(r.weights[0] + r.weights[1], 2.0f), "routed scaling: sum equals factor");
}

// ---------------------------------------------------------------------------
// Control 5: norm_topk_prob = false keeps raw probabilities.
//   softmax [1,2,3], top2 -> [0.6652, 0.2447] (sum < 1).
// ---------------------------------------------------------------------------
static void testNoNorm() {
    std::vector<float> logits = {1.f, 2.f, 3.f};
    RoutingParams p;
    p.scoring = ScoringFunc::Softmax;
    p.topK = 2;
    p.normTopkProb = false;
    p.routedScalingFactor = 1.0f;
    RoutingResult r = Route(logits.data(), 3, p);
    check(approxVec(r.weights, {0.6652f, 0.2447f}), "norm=false: raw softmax weights");
    check(r.weights[0] + r.weights[1] < 0.999f, "norm=false: weights do not sum to 1");
}

// ---------------------------------------------------------------------------
// Control 6: REAP physical-bank masking (retainedExperts).
//   logits [1,2,3,4], retained=2 -> only experts 0,1 routable -> ids [1,0].
// ---------------------------------------------------------------------------
static void testReapRetained() {
    std::vector<float> logits = {1.f, 2.f, 3.f, 4.f};
    RoutingParams p;
    p.scoring = ScoringFunc::Softmax;
    p.topK = 2;
    p.normTopkProb = true;
    p.retainedExperts = 2;  // mask experts >= 2
    p.routedScalingFactor = 1.0f;
    RoutingResult r = Route(logits.data(), 4, p);
    check(idsEqual(r.expertIds, {1, 0}), "reap mask: only retained experts routable (ids [1,0])");
    for (int id : r.expertIds) check(id < 2, "reap mask: no pruned expert selected");
    check(approx(r.weights[0] + r.weights[1], 1.0f), "reap mask: weights renormalized over retained");
}

// ---------------------------------------------------------------------------
// Control 7: Deterministic tie-breaking (lower id wins ties).
// ---------------------------------------------------------------------------
static void testTieBreak() {
    std::vector<float> logits = {0.f, 0.f, 0.f, 0.f, 0.f};
    RoutingParams p;
    p.scoring = ScoringFunc::Softmax;
    p.topK = 3;
    p.normTopkProb = true;
    RoutingResult r = Route(logits.data(), 5, p);
    check(idsEqual(r.expertIds, {0, 1, 2}), "tie-break: lower ids win (0,1,2)");
}

// ---------------------------------------------------------------------------
// Control 8: Numerically stable softmax with large logits (no NaN/Inf).
// ---------------------------------------------------------------------------
static void testSoftmaxStability() {
    std::vector<float> logits = {1000.f, 1001.f};
    std::vector<float> s = Softmax(logits.data(), 2);
    bool finite = std::isfinite(s[0]) && std::isfinite(s[1]);
    check(finite, "stability: softmax finite for large logits");
    check(approx(s[0] + s[1], 1.0f), "stability: softmax sums to 1");
    check(approx(s[0], 0.2689f, 1e-3f) && approx(s[1], 0.7311f, 1e-3f),
          "stability: shifted softmax values correct");
}

// ---------------------------------------------------------------------------
// Control 9: Sigmoid stability for large-magnitude logits.
// ---------------------------------------------------------------------------
static void testSigmoidStability() {
    float sPos = Sigmoid(std::vector<float>{50.f}.data(), 1)[0];
    float sNeg = Sigmoid(std::vector<float>{-50.f}.data(), 1)[0];
    check(std::isfinite(sPos) && std::isfinite(sNeg), "stability: sigmoid finite for +/-50");
    check(approx(sPos, 1.0f, 1e-5f), "stability: sigmoid(+50) ~ 1");
    check(approx(sNeg, 0.0f, 1e-5f), "stability: sigmoid(-50) ~ 0");
}

// ---------------------------------------------------------------------------
// Control 10: ComputeRouterLogits (row-major [numExperts, hiddenDim]).
// ---------------------------------------------------------------------------
static void testRouterLogits() {
    // weights = [[1,0],[0,1]], hidden = [3,4] -> logits = [3,4].
    std::vector<float> w = {1.f, 0.f, 0.f, 1.f};
    std::vector<float> h = {3.f, 4.f};
    std::vector<float> z = ComputeRouterLogits(h.data(), w.data(), 2, 2);
    check(approxVec(z, {3.f, 4.f}), "router logits: dot product layout [numExperts, hiddenDim]");
}

// ---------------------------------------------------------------------------
// Control 11: topK larger than candidate count clamps safely.
// ---------------------------------------------------------------------------
static void testTopKClamp() {
    std::vector<float> logits = {1.f, 2.f};
    RoutingParams p;
    p.scoring = ScoringFunc::Softmax;
    p.topK = 8;  // > numExperts
    RoutingResult r = Route(logits.data(), 2, p);
    check(r.expertIds.size() == 2, "topk clamp: never selects more than numExperts");
    check(approx(r.weights[0] + r.weights[1], 1.0f), "topk clamp: weights normalized");
}

// ---------------------------------------------------------------------------
// Control 12: end-to-end Route with router weights + bias (integration shape).
//   numExperts=4, hiddenDim=2. One-hot-ish hidden selects expert 3.
// ---------------------------------------------------------------------------
static void testEndToEnd() {
    // Router weights: expert e has weight on hidden dim (e % 2).
    // hidden = [0,10]; experts with col1 weight get high logit.
    std::vector<float> w = {
        0.f, 0.f,   // expert 0 -> logit 0
        0.f, 1.f,   // expert 1 -> logit 10
        0.f, 0.f,   // expert 2 -> logit 0
        0.f, 1.f,   // expert 3 -> logit 10
    };
    std::vector<float> h = {0.f, 10.f};
    std::vector<float> logits = ComputeRouterLogits(h.data(), w.data(), 4, 2);
    std::vector<float> bias = {0.f, 0.f, 0.f, 0.f};
    RoutingParams p;
    p.scoring = ScoringFunc::Sigmoid;
    p.topK = 2;
    p.hasCorrectionBias = true;
    p.correctionBias = bias.data();
    p.normTopkProb = true;
    p.routedScalingFactor = 2.827f;
    RoutingResult r = Route(logits.data(), 4, p);
    // sigmoid(10) ~ 1 for experts 1 and 3; top2 -> [1,3].
    check(idsEqual(r.expertIds, {1, 3}), "end-to-end: highest-logit experts selected");
    float sum = 0.f;
    for (float x : r.weights) sum += x;
    check(approx(sum, 2.827f, 1e-2f), "end-to-end: DeepSeek-style scaling sum ~2.827");
}

int main() {
    std::fprintf(stdout, "=== REAP MoE routing core regression ===\n");
    testSoftmaxBasic();
    testSigmoidBiasSelectionOnly();
    testGroupLimited();
    testRoutedScaling();
    testNoNorm();
    testReapRetained();
    testTieBreak();
    testSoftmaxStability();
    testSigmoidStability();
    testRouterLogits();
    testTopKClamp();
    testEndToEnd();
    std::fprintf(stdout, "=== %d checks, %d failures ===\n", g_checks, g_fails);
    if (g_fails == 0) {
        std::fprintf(stdout, "ROUTING_CORE_RESULT=PASS\n");
        return 0;
    }
    std::fprintf(stderr, "ROUTING_CORE_RESULT=FAIL\n");
    return 1;
}