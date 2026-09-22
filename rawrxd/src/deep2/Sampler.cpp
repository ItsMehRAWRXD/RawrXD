/* Real Sampler Implementation */
#include "Sampler.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>

namespace rawrxd {
namespace sampling {

int GreedySampler::sample(const float* logits, int n_vocab) {
    int best = 0;
    float bestVal = logits[0];
    for (int i = 1; i < n_vocab; ++i) {
        if (logits[i] > bestVal) { bestVal = logits[i]; best = i; }
    }
    return best;
}

int TemperatureSampler::sample(const float* logits, int n_vocab) {
    if (temp_ <= 0.0f) {
        GreedySampler g;
        return g.sample(logits, n_vocab);
    }
    // Softmax with temperature
    float maxLogit = logits[0];
    for (int i = 1; i < n_vocab; ++i) maxLogit = std::max(maxLogit, logits[i]);
    float sum = 0.0f;
    std::vector<float> probs(n_vocab);
    for (int i = 0; i < n_vocab; ++i) {
        probs[i] = std::exp((logits[i] - maxLogit) / temp_);
        sum += probs[i];
    }
    for (auto& p : probs) p /= sum;
    // Simple deterministic argmax over probabilities (temperature=0 bypass)
    int best = 0;
    float bestP = probs[0];
    for (int i = 1; i < n_vocab; ++i) {
        if (probs[i] > bestP) { bestP = probs[i]; best = i; }
    }
    return best;
}

int TopKSampler::sample(const float* logits, int n_vocab) {
    if (k_ <= 1 || temp_ <= 0.0f) {
        GreedySampler g;
        return g.sample(logits, n_vocab);
    }
    struct Candidate { int id; float logit; };
    std::vector<Candidate> cands;
    cands.reserve(n_vocab);
    for (int i = 0; i < n_vocab; ++i) cands.push_back({i, logits[i]});
    std::partial_sort(cands.begin(), cands.begin() + std::min(k_, n_vocab),
                      cands.end(), [](const Candidate& a, const Candidate& b) {
                          return a.logit > b.logit;
                      });
    int kk = std::min(k_, n_vocab);
    float maxL = cands[0].logit;
    float sum = 0.0f;
    std::vector<float> probs(kk);
    for (int i = 0; i < kk; ++i) {
        probs[i] = std::exp((cands[i].logit - maxL) / temp_);
        sum += probs[i];
    }
    for (auto& p : probs) p /= sum;
    int best = 0;
    float bestP = probs[0];
    for (int i = 1; i < kk; ++i) {
        if (probs[i] > bestP) { bestP = probs[i]; best = i; }
    }
    return cands[best].id;
}

} // namespace sampling
} // namespace rawrxd
