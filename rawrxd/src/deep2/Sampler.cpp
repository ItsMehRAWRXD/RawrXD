/* Real Sampler Implementation */
#include "Sampler.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <functional>

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

// ============================================================================
// RAWRXD_BATCH_02_SAMPLER_GATE_001 implementations.
// ============================================================================

// Categorical draw over normalized probabilities using xorshift64 RNG. Templated
// on the RNG callable so a capturing lambda binds without conversion to a
// function pointer and without the per-draw std::function allocation.
// Caller passes already-softmaxed probs summing to ~1.0.
template <class Rand>
static int categoricalDraw(const std::vector<float>& probs, Rand&& nextRand) {
    constexpr double INV_2_64 = 1.0 / 18446744073709551616.0; // 2^-64
    double u = (double)nextRand() * INV_2_64;
    double cum = 0.0;
    for (size_t i = 0; i < probs.size(); ++i) {
        cum += probs[i];
        if (u <= cum) return (int)i;
    }
    return (int)(probs.size() - 1);
}

int TopPSampler::sample(const float* logits, int n_vocab) {
    if (n_vocab <= 0) return 0;
    if (temp_ <= 0.0f) { GreedySampler g; return g.sample(logits, n_vocab); }
    if (p_ >= 1.0f) {
        // topP=1 == pure temperature sampler
        TemperatureSampler t(temp_); return t.sample(logits, n_vocab);
    }
    if (p_ <= 0.0f) { GreedySampler g; return g.sample(logits, n_vocab); }
    // Compute softmax probs
    float maxL = logits[0];
    for (int i = 1; i < n_vocab; ++i) maxL = std::max(maxL, logits[i]);
    std::vector<float> probs(n_vocab);
    double sum = 0.0;
    for (int i = 0; i < n_vocab; ++i) {
        probs[i] = (float)std::exp((double)(logits[i] - maxL) / (double)temp_);
        sum += probs[i];
    }
    for (auto& x : probs) x /= (float)sum;
    // Sort indices by prob desc
    std::vector<int> idx(n_vocab);
    std::iota(idx.begin(), idx.end(), 0);
    std::sort(idx.begin(), idx.end(), [&](int a, int b){ return probs[a] > probs[b]; });
    // Find nucleus: smallest set with cumulative prob >= p_
    double cum = 0.0;
    int cutoff = n_vocab;
    for (int i = 0; i < n_vocab; ++i) {
        cum += probs[idx[i]];
        if (cum >= (double)p_) { cutoff = i + 1; break; }
    }
    // Renormalize within cutoff and draw
    std::vector<float> np(cutoff);
    double s = 0.0;
    for (int i = 0; i < cutoff; ++i) { np[i] = probs[idx[i]]; s += np[i]; }
    for (auto& x : np) x /= (float)s;
    int pick = categoricalDraw(np, [this](){ return this->nextRand(); });
    return idx[pick];
}

int MinPSampler::sample(const float* logits, int n_vocab) {
    if (n_vocab <= 0) return 0;
    if (temp_ <= 0.0f) { GreedySampler g; return g.sample(logits, n_vocab); }
    if (minP_ <= 0.0f) { TemperatureSampler t(temp_); return t.sample(logits, n_vocab); }
    if (minP_ >= 1.0f) { GreedySampler g; return g.sample(logits, n_vocab); }
    // Compute softmax probs
    float maxL = logits[0];
    for (int i = 1; i < n_vocab; ++i) maxL = std::max(maxL, logits[i]);
    std::vector<float> probs(n_vocab);
    double sum = 0.0;
    for (int i = 0; i < n_vocab; ++i) {
        probs[i] = (float)std::exp((double)(logits[i] - maxL) / (double)temp_);
        sum += probs[i];
    }
    for (auto& x : probs) x /= (float)sum;
    // max prob is the anchor; keep only tokens with prob >= minP * maxProb
    float maxP = probs[0];
    for (auto x : probs) maxP = std::max(maxP, x);
    float threshold = minP_ * maxP;
    std::vector<float> filt;
    std::vector<int> idxMap;
    filt.reserve(n_vocab);
    idxMap.reserve(n_vocab);
    double s = 0.0;
    for (int i = 0; i < n_vocab; ++i) {
        if (probs[i] >= threshold) {
            filt.push_back(probs[i]);
            idxMap.push_back(i);
            s += probs[i];
        }
    }
    if (filt.empty()) { GreedySampler g; return g.sample(logits, n_vocab); }
    for (auto& x : filt) x /= (float)s;
    int pick = categoricalDraw(filt, [this](){ return this->nextRand(); });
    return idxMap[pick];
}

void RepetitionPenaltyProcessor::apply(float* logits, int n_vocab, const int* priorTokens, int nPrior) const {
    if (!active() || !priorTokens || nPrior <= 0) return;
    for (int i = 0; i < nPrior; ++i) {
        int t = priorTokens[i];
        if (t >= 0 && t < n_vocab) {
            if (logits[t] > 0.0f) logits[t] /= penalty_;
            else logits[t] *= penalty_;
        }
    }
}

int CombinedSampler::sample(const float* logits, int n_vocab) {
    if (n_vocab <= 0) return 0;
    if (temp_ <= 0.0f) { GreedySampler g; return g.sample(logits, n_vocab); }
    // Compute softmax probs
    float maxL = logits[0];
    for (int i = 1; i < n_vocab; ++i) maxL = std::max(maxL, logits[i]);
    std::vector<float> probs(n_vocab);
    double sum = 0.0;
    for (int i = 0; i < n_vocab; ++i) {
        probs[i] = (float)std::exp((double)(logits[i] - maxL) / (double)temp_);
        sum += probs[i];
    }
    for (auto& x : probs) x /= (float)sum;
    // `idx[p]` is the token id for position p, and `probs` is kept positionally
    // aligned with it. The top-k step shortens both together, so a token id is
    // never used to index probs: before this fix the top-p sort below did
    // exactly that, indexing a topK-sized probability vector with vocab ids as
    // large as n_vocab.
    std::vector<int> idx(n_vocab);
    std::iota(idx.begin(), idx.end(), 0);
    // Step 1: keep topK
    if (topK_ > 0 && (uint32_t)topK_ < (uint32_t)n_vocab) {
        const int keep = (int)topK_;
        std::partial_sort(idx.begin(), idx.begin() + keep, idx.end(),
                          [&](int a, int b){ return probs[a] > probs[b]; });
        idx.resize(keep);
        // Renormalize within topK
        double s = 0.0;
        for (int i = 0; i < keep; ++i) s += probs[idx[i]];
        std::vector<float> kp(keep);
        for (int i = 0; i < keep; ++i) kp[i] = (float)(probs[idx[i]] / s);
        probs.swap(kp);
    }
    // Step 2: topP nucleus. `order` holds positions, so both the sort and the
    // probability reads stay inside the narrowed vector.
    if (topP_ > 0.0f && topP_ < 1.0f) {
        std::vector<int> order(probs.size());
        std::iota(order.begin(), order.end(), 0);
        std::sort(order.begin(), order.end(),
                  [&](int a, int b){ return probs[a] > probs[b]; });
        double cum = 0.0;
        size_t cutoff = order.size();
        for (size_t i = 0; i < order.size(); ++i) {
            cum += probs[order[i]];
            if (cum >= (double)topP_) { cutoff = i + 1; break; }
        }
        std::vector<float> np(cutoff);
        double s = 0.0;
        for (size_t i = 0; i < cutoff; ++i) { np[i] = probs[order[i]]; s += np[i]; }
        for (auto& x : np) x /= (float)s;
        int pick = categoricalDraw(np, [this](){ return this->nextRand(); });
        return idx[order[pick]];
    }
    // Step 3: minP
    if (minP_ > 0.0f) {
        float maxP = 0.0f;
        for (auto x : probs) maxP = std::max(maxP, x);
        float threshold = minP_ * maxP;
        std::vector<float> filt;
        std::vector<int> idxMap;
        double s = 0.0;
        for (size_t i = 0; i < probs.size(); ++i) {
            if (probs[i] >= threshold) {
                filt.push_back(probs[i]);
                idxMap.push_back((int)i);
                s += probs[i];
            }
        }
        if (!filt.empty()) {
            for (auto& x : filt) x /= (float)s;
            int pick = categoricalDraw(filt, [this](){ return this->nextRand(); });
            return idx[idxMap[pick]];
        }
    }
    // Pure temperature fallback over the surviving positions.
    int pick = categoricalDraw(probs, [this](){ return this->nextRand(); });
    return idx[pick];
}

} // namespace sampling
} // namespace rawrxd
