// ============================================================================
// MoERoutingCore.hpp — Single native, metadata-driven MoE routing core.
//
// This is the ONE authoritative routing implementation shared by every
// execution path (Deep2 single-file, multi-shard, REAP calibration, Vulkan
// expert dispatch, IDE inference). Architecture-specific behavior is expressed
// through RoutingParams, never by duplicating routing math or hardcoding
// expert counts.
//
// Correct DeepSeek-V3 / Kimi-K2 sigmoid routing:
//     s_i = sigmoid(z_i)                 (activated score)
//     c_i = s_i + b_i                    (selection score, bias is SELECTION-ONLY)
//     group selection on c_i (optional)  (top-2 sum per group → top groups)
//     S   = top-k over c_i among allowed groups
//     w_i = s_i  (UNBIASED)              → normalize (if normTopkProb)
//                                        → × routedScalingFactor
// Correct softmax routing (Qwen/Mixtral style):
//     p_i = softmax(z_i)
//     S   = top-k over p_i
//     w_i = p_i → normalize (if normTopkProb) → × routedScalingFactor
//
// The correction bias NEVER contaminates the final expert weights. Selection and
// weighting are separate concerns.
//
// Native only. No external dependencies. No stubs.
// ============================================================================
#pragma once

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <numeric>
#include <vector>

namespace Deep2 {
namespace moe {

enum class ScoringFunc : int {
    Softmax = 0,  // llama.cpp LLAMA_EXPERT_GATING_FUNC_TYPE_SOFTMAX
    Sigmoid = 1,  // llama.cpp LLAMA_EXPERT_GATING_FUNC_TYPE_SIGMOID
};

// Map a metadata gating-func value to a ScoringFunc. llama.cpp stores
// `expert_gating_func` as: 1 = softmax, 2 = sigmoid (0/absent = softmax).
// Some converters also emit the string `scoring_func` ("sigmoid"/"softmax").
inline ScoringFunc ScoringFuncFromGatingValue(uint32_t gatingFunc) {
    return (gatingFunc == 2u) ? ScoringFunc::Sigmoid : ScoringFunc::Softmax;
}

inline ScoringFunc ScoringFuncFromName(const char* name) {
    if (!name) return ScoringFunc::Softmax;
    // Case-insensitive compare for "sigmoid".
    const char* s = name;
    const char* target = "sigmoid";
    while (*s && *target) {
        char a = *s;
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
        if (a != *target) return ScoringFunc::Softmax;
        ++s;
        ++target;
    }
    return (*target == '\0') ? ScoringFunc::Sigmoid : ScoringFunc::Softmax;
}

// All architecture-dependent routing parameters in one place.
struct RoutingParams {
    ScoringFunc scoring = ScoringFunc::Softmax;

    int topK = 0;          // experts per token (numExpertsPerToken / expert_used_count)

    int nGroup = 1;        // expert groups; <= 1 disables group-limited routing
    int topkGroup = 0;     // groups to keep; <= 0 or >= nGroup disables limiting

    bool hasCorrectionBias = false;
    const float* correctionBias = nullptr;  // [numExperts], selection-only

    bool normTopkProb = true;               // renormalize selected weights to sum 1
    float routedScalingFactor = 1.0f;       // multiply final weights (DeepSeek: ~2.827)

    // REAP physical bank: experts with id >= retainedExperts are permanently
    // masked from routing. 0 disables the exclusion (full topology).
    int retainedExperts = 0;
};

struct RoutingResult {
    std::vector<int> expertIds;    // selected experts, descending selection score
    std::vector<float> weights;    // FINAL coefficients, aligned with expertIds
    std::vector<float> scores;     // activated scores per expert (post activation)
    std::vector<float> choices;    // selection scores per expert (scores + bias)
    bool groupLimited = false;     // whether group limiting was applied
};

// ---------------------------------------------------------------------------
// Activation functions
// ---------------------------------------------------------------------------

// Numerically stable softmax over n logits.
inline std::vector<float> Softmax(const float* logits, int n) {
    std::vector<float> out(static_cast<size_t>(n));
    if (n <= 0) return out;
    float maxLogit = logits[0];
    for (int i = 1; i < n; ++i) maxLogit = std::max(maxLogit, logits[i]);
    float sum = 0.0f;
    for (int i = 0; i < n; ++i) {
        float e = std::exp(logits[i] - maxLogit);
        out[static_cast<size_t>(i)] = e;
        sum += e;
    }
    if (sum > 0.0f) {
        const float inv = 1.0f / sum;
        for (int i = 0; i < n; ++i) out[static_cast<size_t>(i)] *= inv;
    }
    return out;
}

// Numerically stable sigmoid over n logits.
inline std::vector<float> Sigmoid(const float* logits, int n) {
    std::vector<float> out(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        const float x = logits[i];
        // Avoid overflow: branch on sign.
        float s;
        if (x >= 0.0f) {
            s = 1.0f / (1.0f + std::exp(-x));
        } else {
            const float ex = std::exp(x);
            s = ex / (1.0f + ex);
        }
        out[static_cast<size_t>(i)] = s;
    }
    return out;
}

// Compute router logits: z_e = dot(routerWeights[e, :], hidden).
// routerWeights is row-major [numExperts, hiddenDim].
inline std::vector<float> ComputeRouterLogits(const float* hidden,
                                              const float* routerWeights,
                                              int numExperts,
                                              int hiddenDim) {
    std::vector<float> logits(static_cast<size_t>(numExperts));
    for (int e = 0; e < numExperts; ++e) {
        const float* row = routerWeights + static_cast<size_t>(e) * static_cast<size_t>(hiddenDim);
        float acc = 0.0f;
        for (int d = 0; d < hiddenDim; ++d) acc += row[d] * hidden[d];
        logits[static_cast<size_t>(e)] = acc;
    }
    return logits;
}

// ---------------------------------------------------------------------------
// Core routing
// ---------------------------------------------------------------------------
// logits -> selected expert ids + final weights, per the params above.
// Deterministic: ties break toward the lower expert id (stable).
inline RoutingResult Route(const float* logits, int numExperts,
                           const RoutingParams& params) {
    RoutingResult result;
    if (numExperts <= 0 || logits == nullptr) return result;

    // 1) Activated scores.
    if (params.scoring == ScoringFunc::Sigmoid) {
        result.scores = Sigmoid(logits, numExperts);
    } else {
        result.scores = Softmax(logits, numExperts);
    }

    // 2) Selection scores = activated scores + correction bias (selection-only).
    result.choices = result.scores;
    if (params.hasCorrectionBias && params.correctionBias != nullptr) {
        for (int e = 0; e < numExperts; ++e) {
            result.choices[static_cast<size_t>(e)] += params.correctionBias[e];
        }
    }

    // 3) REAP physical-bank masking (experts >= retainedExperts are unroutable).
    auto isAllowed = [&](int e) -> bool {
        if (params.retainedExperts > 0 && e >= params.retainedExperts) return false;
        return true;
    };

    // 4) Group-limited routing (optional).
    //    Group score = sum of the top-2 selection scores within the group.
    //    Keep the top `topkGroup` groups; mask experts outside them.
    std::vector<char> allowed(static_cast<size_t>(numExperts), 1);
    int nGroup = params.nGroup;
    int topkGroup = params.topkGroup;
    if (nGroup > 1 && numExperts % nGroup == 0 && topkGroup > 0 && topkGroup < nGroup) {
        const int perGroup = numExperts / nGroup;
        std::vector<float> groupScore(static_cast<size_t>(nGroup), 0.0f);
        for (int g = 0; g < nGroup; ++g) {
            // Find top-2 selection scores in this group.
            float first = -std::numeric_limits<float>::infinity();
            float second = -std::numeric_limits<float>::infinity();
            for (int j = 0; j < perGroup; ++j) {
                const int e = g * perGroup + j;
                const float c = result.choices[static_cast<size_t>(e)];
                if (c > first) {
                    second = first;
                    first = c;
                } else if (c > second) {
                    second = c;
                }
            }
            groupScore[static_cast<size_t>(g)] = first + second;
        }
        // Select top `topkGroup` groups by score; ties → lower group index.
        std::vector<int> gidx(static_cast<size_t>(nGroup));
        std::iota(gidx.begin(), gidx.end(), 0);
        std::partial_sort(gidx.begin(), gidx.begin() + topkGroup, gidx.end(),
                          [&](int a, int b) {
                              if (groupScore[static_cast<size_t>(a)] != groupScore[static_cast<size_t>(b)])
                                  return groupScore[static_cast<size_t>(a)] > groupScore[static_cast<size_t>(b)];
                              return a < b;
                          });
        std::fill(allowed.begin(), allowed.end(), static_cast<char>(0));
        for (int i = 0; i < topkGroup; ++i) {
            const int g = gidx[static_cast<size_t>(i)];
            for (int j = 0; j < perGroup; ++j) allowed[static_cast<size_t>(g * perGroup + j)] = 1;
        }
        result.groupLimited = true;
    }

    // 5) Top-k over selection scores among allowed experts.
    //    Build the candidate index list.
    std::vector<int> candidates;
    candidates.reserve(static_cast<size_t>(numExperts));
    for (int e = 0; e < numExperts; ++e) {
        if (allowed[static_cast<size_t>(e)] && isAllowed(e)) candidates.push_back(e);
    }

    int k = params.topK;
    if (k <= 0) k = static_cast<int>(candidates.size());
    if (k > static_cast<int>(candidates.size())) k = static_cast<int>(candidates.size());

    // Deterministic partial sort by selection score desc, tie → lower expert id.
    std::partial_sort(candidates.begin(), candidates.begin() + k, candidates.end(),
                      [&](int a, int b) {
                          const float ca = result.choices[static_cast<size_t>(a)];
                          const float cb = result.choices[static_cast<size_t>(b)];
                          if (ca != cb) return ca > cb;
                          return a < b;
                      });

    result.expertIds.assign(candidates.begin(), candidates.begin() + k);

    // 6) Final weights from UNBIASED activated scores (never the choice scores).
    result.weights.resize(static_cast<size_t>(k));
    float sum = 0.0f;
    for (int i = 0; i < k; ++i) {
        const int e = result.expertIds[static_cast<size_t>(i)];
        const float w = result.scores[static_cast<size_t>(e)];
        result.weights[static_cast<size_t>(i)] = w;
        sum += w;
    }
    if (params.normTopkProb && sum > 0.0f) {
        const float inv = 1.0f / sum;
        for (int i = 0; i < k; ++i) result.weights[static_cast<size_t>(i)] *= inv;
    }
    const float scale = params.routedScalingFactor;
    if (scale != 1.0f) {
        for (int i = 0; i < k; ++i) result.weights[static_cast<size_t>(i)] *= scale;
    }

    return result;
}

}  // namespace moe
}  // namespace Deep2