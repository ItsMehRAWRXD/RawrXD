#pragma once
// ============================================================================
// MoERouter.hpp — Batch 8 real deterministic MoE top-k router
// - softmax / sigmoid / sqrt-softplus scoring
// - optional group-limited top-k
// - selected-weight normalization + scale
// - no fake routing / no dense fallback
// ============================================================================
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <numeric>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace Deep2 {

struct WeightTensor; // defined by Deep2Engine.h after this header is included

enum class MoEGatingFunc : uint32_t {
    None            = 0,
    Softmax         = 1,
    Sigmoid         = 2,
    SoftmaxWeight   = 3, // requires pre-softmaxed router weights; unsupported here
    SqrtSoftplus    = 4,
};

struct MoEConfig {
    size_t numExperts = 0;
    size_t expertsPerToken = 0;

    // Compatibility names used by the production tree.
    size_t numActiveExperts = 0;
    size_t hiddenDim = 0;
    size_t expertDim = 0;
    size_t sharedExpertDim = 0;
    size_t numSharedExperts = 0;
    bool useSharedExpert = false;

    MoEGatingFunc gatingFunc = MoEGatingFunc::Softmax;
    float expertWeightsScale = 1.0f;
    bool normalizeSelectedWeights = true;

    // DeepSeek/GLM style group-limited routing. Zero disables group filtering.
    size_t expertGroupCount = 0;
    size_t expertGroupUsedCount = 0;
    size_t expertsPerGroup = 0;
};

struct TokenRoute {
    bool valid = false;
    std::vector<int> expertIds;
    std::vector<float> expertWeights;
    std::vector<float> selectedScores;
};

struct MoEWeightHandle {
    int layer = -1;
    int expert = -1;
    const WeightTensor* gate = nullptr;
    const WeightTensor* up = nullptr;
    const WeightTensor* down = nullptr;
    size_t bytes = 0;

    bool valid() const noexcept {
        return layer >= 0 && expert >= 0 && gate && up && down;
    }
};

class MoERouter {
public:
    explicit MoERouter(int n = 0) {
        if (n > 0) {
            MoEConfig cfg;
            cfg.numExperts = static_cast<size_t>(n);
            cfg.expertsPerToken = std::min<size_t>(2, cfg.numExperts);
            cfg.numActiveExperts = cfg.expertsPerToken;
            (void)Initialize(cfg);
        }
    }

    bool Initialize(const MoEConfig& cfg) {
        config_ = cfg;
        if (config_.expertsPerToken == 0)
            config_.expertsPerToken = config_.numActiveExperts;
        if (config_.numActiveExperts == 0)
            config_.numActiveExperts = config_.expertsPerToken;

        const size_t k = config_.expertsPerToken;
        if (config_.numExperts == 0 || k == 0 || k > config_.numExperts)
            return false;
        if (!(config_.expertWeightsScale > 0.0f) ||
            !std::isfinite(config_.expertWeightsScale))
            return false;

        if (config_.expertGroupCount > 0) {
            if (config_.expertGroupUsedCount == 0 ||
                config_.expertGroupUsedCount > config_.expertGroupCount)
                return false;
            if (config_.expertsPerGroup == 0) {
                config_.expertsPerGroup =
                    (config_.numExperts + config_.expertGroupCount - 1) /
                    config_.expertGroupCount;
            }
        }

        expertLoads_.assign(config_.numExperts, 0);
        routerWeights_.clear();
        routerRows_ = routerCols_ = 0;
        lastRoute_ = {};
        initialized_ = true;
        return true;
    }

    bool SetRouterWeights(const float* weights, size_t rows, size_t cols) {
        if (!initialized_ || !weights ||
            rows != config_.numExperts || cols == 0)
            return false;
        if (config_.hiddenDim != 0 && cols != config_.hiddenDim)
            return false;

        const size_t count = rows * cols;
        if (rows != 0 && count / rows != cols) return false;
        routerWeights_.assign(weights, weights + count);
        routerRows_ = rows;
        routerCols_ = cols;
        return true;
    }

    TokenRoute Route(const float* hidden) {
        TokenRoute bad;
        if (!hidden || routerWeights_.empty() ||
            routerRows_ != config_.numExperts || routerCols_ == 0)
            return bad;

        std::vector<float> logits(routerRows_, 0.0f);
        for (size_t e = 0; e < routerRows_; ++e) {
            const float* row = routerWeights_.data() + e * routerCols_;
            double acc = 0.0;
            for (size_t c = 0; c < routerCols_; ++c)
                acc += static_cast<double>(row[c]) *
                       static_cast<double>(hidden[c]);
            logits[e] = static_cast<float>(acc);
        }
        return RouteFromLogits(logits.data(), logits.size());
    }

    TokenRoute RouteFromLogits(const float* logits, size_t count) {
        TokenRoute route;
        if (!initialized_ || !logits || count != config_.numExperts)
            return route;
        if (config_.gatingFunc == MoEGatingFunc::None ||
            config_.gatingFunc == MoEGatingFunc::SoftmaxWeight)
            return route; // fail closed: needs architecture-specific weight preprocessing

        std::vector<float> scores(count, 0.0f);
        for (size_t i = 0; i < count; ++i) {
            const float x = logits[i];
            if (!std::isfinite(x)) return route;
            scores[i] = scoreValue(x);
            if (!std::isfinite(scores[i]))
                return route;
            if (config_.gatingFunc != MoEGatingFunc::Softmax &&
                scores[i] < 0.0f)
                return route;
        }

        std::vector<uint8_t> allowed(count, 1);
        if (!applyGroupMask(scores, allowed))
            return route;

        std::vector<int> candidates;
        candidates.reserve(count);
        for (size_t i = 0; i < count; ++i)
            if (allowed[i]) candidates.push_back(static_cast<int>(i));

        const size_t k = config_.expertsPerToken;
        if (candidates.size() < k) return route;

        // Stable deterministic top-k: score descending, ID ascending on ties.
        std::partial_sort(
            candidates.begin(), candidates.begin() + static_cast<std::ptrdiff_t>(k),
            candidates.end(),
            [&](int a, int b) {
                if (scores[static_cast<size_t>(a)] !=
                    scores[static_cast<size_t>(b)])
                    return scores[static_cast<size_t>(a)] >
                           scores[static_cast<size_t>(b)];
                return a < b;
            });
        candidates.resize(k);

        route.expertIds = candidates;
        route.selectedScores.reserve(k);
        for (int id : candidates)
            route.selectedScores.push_back(scores[static_cast<size_t>(id)]);

        if (!computeWeights(logits, scores, allowed, route))
            return TokenRoute{};

        route.valid = route.expertIds.size() == k &&
                      route.expertWeights.size() == k;
        if (!route.valid) return TokenRoute{};

        for (int id : route.expertIds)
            ++expertLoads_[static_cast<size_t>(id)];
        lastRoute_ = route;
        return route;
    }

    // Compatibility with the original stub signature.
    std::vector<int> route(const float* hidden, int k) {
        if (!hidden || k <= 0 || !initialized_) return {};
        if (static_cast<size_t>(k) != config_.expertsPerToken) return {};
        TokenRoute r = Route(hidden);
        return r.valid ? r.expertIds : std::vector<int>{};
    }

    std::vector<int> GetLastRouteExpertIds() const {
        return lastRoute_.expertIds;
    }

    const TokenRoute& lastRoute() const noexcept { return lastRoute_; }
    const MoEConfig& config() const noexcept { return config_; }

    void ResetStats() { lastRoute_ = {}; }
    void ResetExpertLoads() {
        std::fill(expertLoads_.begin(), expertLoads_.end(), 0);
    }
    const std::vector<uint64_t>& expertLoads() const noexcept {
        return expertLoads_;
    }

private:
    static float sigmoid(float x) {
        if (x >= 0.0f) {
            const float z = std::exp(-x);
            return 1.0f / (1.0f + z);
        }
        const float z = std::exp(x);
        return z / (1.0f + z);
    }

    static float softplus(float x) {
        if (x > 20.0f) return x;
        if (x < -20.0f) return std::exp(x);
        return std::log1p(std::exp(x));
    }

    float scoreValue(float x) const {
        switch (config_.gatingFunc) {
            case MoEGatingFunc::Softmax:
                // exp is applied with a global max inside computeWeights;
                // ranking by the raw logit is equivalent.
                return x;
            case MoEGatingFunc::Sigmoid:
                return sigmoid(x);
            case MoEGatingFunc::SqrtSoftplus:
                return std::sqrt(std::max(0.0f, softplus(x)));
            default:
                return -1.0f;
        }
    }

    bool applyGroupMask(const std::vector<float>& scores,
                        std::vector<uint8_t>& allowed) const {
        if (config_.expertGroupCount == 0) return true;

        const size_t groupCount = config_.expertGroupCount;
        const size_t perGroup = config_.expertsPerGroup;
        if (groupCount == 0 || perGroup == 0) return false;

        struct GroupScore { float score; size_t group; };
        std::vector<GroupScore> groups;
        groups.reserve(groupCount);

        for (size_t g = 0; g < groupCount; ++g) {
            const size_t lo = g * perGroup;
            if (lo >= scores.size()) {
                groups.push_back({-std::numeric_limits<float>::infinity(), g});
                continue;
            }
            const size_t hi = std::min(scores.size(), lo + perGroup);

            // DeepSeek-style group score: sum of the best two experts in group.
            float best1 = -std::numeric_limits<float>::infinity();
            float best2 = -std::numeric_limits<float>::infinity();
            for (size_t i = lo; i < hi; ++i) {
                const float s = scores[i];
                if (s > best1) { best2 = best1; best1 = s; }
                else if (s > best2) { best2 = s; }
            }
            if (!std::isfinite(best1)) return false;
            if (!std::isfinite(best2)) best2 = 0.0f;
            groups.push_back({best1 + best2, g});
        }

        const size_t use = config_.expertGroupUsedCount;
        if (use == 0 || use > groups.size()) return false;
        std::partial_sort(
            groups.begin(), groups.begin() + static_cast<std::ptrdiff_t>(use),
            groups.end(),
            [](const GroupScore& a, const GroupScore& b) {
                if (a.score != b.score) return a.score > b.score;
                return a.group < b.group;
            });

        std::fill(allowed.begin(), allowed.end(), uint8_t{0});
        for (size_t j = 0; j < use; ++j) {
            const size_t g = groups[j].group;
            const size_t lo = g * perGroup;
            const size_t hi = std::min(scores.size(), lo + perGroup);
            for (size_t i = lo; i < hi; ++i) allowed[i] = 1;
        }
        return true;
    }

    bool computeWeights(const float* logits,
                        const std::vector<float>& scores,
                        const std::vector<uint8_t>& allowed,
                        TokenRoute& route) const {
        const size_t n = scores.size();
        route.expertWeights.assign(route.expertIds.size(), 0.0f);

        if (config_.gatingFunc == MoEGatingFunc::Softmax) {
            float maxLogit = -std::numeric_limits<float>::infinity();
            for (size_t i = 0; i < n; ++i)
                if (allowed[i]) maxLogit = std::max(maxLogit, logits[i]);
            if (!std::isfinite(maxLogit)) return false;

            double denom = 0.0;
            for (size_t i = 0; i < n; ++i)
                if (allowed[i]) denom += std::exp(
                    static_cast<double>(logits[i] - maxLogit));
            if (!(denom > 0.0) || !std::isfinite(denom)) return false;

            for (size_t j = 0; j < route.expertIds.size(); ++j) {
                const size_t id = static_cast<size_t>(route.expertIds[j]);
                route.expertWeights[j] = static_cast<float>(
                    std::exp(static_cast<double>(logits[id] - maxLogit)) / denom);
            }
        } else {
            for (size_t j = 0; j < route.expertIds.size(); ++j) {
                const size_t id = static_cast<size_t>(route.expertIds[j]);
                route.expertWeights[j] = scores[id];
            }
        }

        if (config_.normalizeSelectedWeights) {
            double sum = 0.0;
            for (float w : route.expertWeights) sum += w;
            if (!(sum > 0.0) || !std::isfinite(sum)) return false;
            for (float& w : route.expertWeights)
                w = static_cast<float>(w / sum);
        }

        for (float& w : route.expertWeights) {
            w *= config_.expertWeightsScale;
            if (!std::isfinite(w)) return false;
        }
        return true;
    }

    MoEConfig config_{};
    bool initialized_ = false;

    std::vector<float> routerWeights_;
    size_t routerRows_ = 0;
    size_t routerCols_ = 0;

    std::vector<uint64_t> expertLoads_;
    TokenRoute lastRoute_{};
};

// Compatibility shells retained for the broader production header. They do not
// claim loading/prefetch authority in this batch.
class MoELayer {
public:
    virtual ~MoELayer() = default;
};
class MoEWeightsLoader {
public:
    virtual ~MoEWeightsLoader() = default;
};
class MoEWeightProxy {
public:
    virtual ~MoEWeightProxy() = default;
};

} // namespace Deep2
