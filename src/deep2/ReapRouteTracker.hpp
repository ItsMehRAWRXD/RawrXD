#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <cmath>

namespace Deep2 {

// Opt-in observer used only by the real CPU calibration pass. It is inert
// unless explicitly installed by the caller, so normal inference is unchanged.
class ReapRouteTracker final {
public:
    using Observer = std::function<void(std::size_t,
                                        const std::vector<float>&,
                                        const std::vector<int>&,
                                        const std::vector<float>&)>;

    static ReapRouteTracker& Instance() {
        static ReapRouteTracker tracker;
        return tracker;
    }

    void Install(Observer observer) {
        std::lock_guard<std::mutex> lock(mu_);
        observer_ = std::move(observer);
    }

    void Clear() {
        std::lock_guard<std::mutex> lock(mu_);
        observer_ = {};
    }

    void Observe(std::size_t layer, const std::vector<float>& probabilities,
                 const std::vector<int>& expertIds,
                 const std::vector<float>& weights) const {
        Observer copy;
        {
            std::lock_guard<std::mutex> lock(mu_);
            copy = observer_;
        }
        if (copy) copy(layer, probabilities, expertIds, weights);
    }

private:
    mutable std::mutex mu_;
    Observer observer_;
};

// Deterministic aggregation used by a real calibration caller.  It records
// only observations delivered by MoERouter; it never invents routes or
// changes routing decisions.  Keys are layer/expert pairs so architectures
// with different layer/expert counts remain isolated.
struct ReapExpertMetric {
    uint64_t routeCount = 0;
    double activationSum = 0.0;
    double weightSum = 0.0;
};

class ReapActivationAccumulator final {
public:
    struct PairHash { size_t operator()(const std::pair<size_t,size_t>& p) const noexcept { return p.first * 1315423911u ^ p.second; } };
    void Reset() { std::lock_guard<std::mutex> l(mu_); metrics_.clear(); tokens_ = 0; }
    void Observe(std::size_t layer, const std::vector<float>& probabilities,
                 const std::vector<int>& ids, const std::vector<float>& weights) {
        std::lock_guard<std::mutex> l(mu_);
        ++tokens_;
        for (size_t i = 0; i < ids.size() && i < weights.size(); ++i) {
            const int e = ids[i];
            if (e < 0 || !std::isfinite(weights[i])) continue;
            auto& m = metrics_[std::make_pair(layer, static_cast<size_t>(e))];
            ++m.routeCount;
            m.activationSum += std::fabs(static_cast<double>(weights[i]));
            m.weightSum += static_cast<double>(weights[i]);
        }
        (void)probabilities; // retained in the callback contract for auditing
    }
    uint64_t tokenCount() const { std::lock_guard<std::mutex> l(mu_); return tokens_; }
    std::unordered_map<std::pair<size_t,size_t>, ReapExpertMetric,
        PairHash> Snapshot() const { std::lock_guard<std::mutex> l(mu_); return metrics_; }
private:
    mutable std::mutex mu_;
    std::unordered_map<std::pair<size_t,size_t>, ReapExpertMetric, PairHash> metrics_;
    uint64_t tokens_ = 0;
};

} // namespace Deep2
