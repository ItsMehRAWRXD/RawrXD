// ============================================================================
// rawrxd_sampler.h â€” token sampler used by the generation adapters
//
// RAWRXD_UNSIMULATE_001 / RAWRXD_END_TO_END_STATE_001
//
// `src/generation/integration/RawrXDEngineAdapter.h` includes "../../rawrxd_sampler.h"
// for `RawrXDSampler`, and that header has never existed, so the adapter and
// everything including it has never compiled.
//
// IMPORTANT â€” this is an ADAPTER-SIDE sampler, not the production one.
//
// The engine that actually generates tokens is Deep2Engine, and its sampling is
// in src/deep2/Sampler.hpp and src/deep2/Deep2Engine.cpp (sampleToken). That is
// the path every certification in this tree measures, and it is untouched by
// this header.
//
// This type exists for RawrXDEngineAdapter::generate(), which drives a
// RawrXD::CPUInferenceEngine rather than Deep2Engine. Keeping the two apart is
// the point: a sampler here must not become an alternative answer to "what token
// comes next", or the adapters would have their own model behaviour that no
// gate ever sees.
//
// Semantics are ordinary: temperature 0 is greedy argmax, top_k 0 disables
// top-k, top_p in (0,1] disables nucleus truncation. Sampling draws from a
// caller-supplied RNG so a run is reproducible when the caller wants it to be.
// ============================================================================
#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <functional>
#include <random>
#include <vector>

namespace RawrXD {

struct SamplerConfig {
    float    temperature = 0.0f;   // <= 0 means greedy argmax
    float    top_p        = 1.0f;   // in (0, 1]; 1.0 disables nucleus truncation
    int      top_k        = 0;      // <= 0 disables top-k
    float    min_p        = 0.0f;   // in [0, 1]; 0.0 disables min-p truncation
    float    repetition_penalty = 1.0f;  // 1.0 disables
    uint32_t seed        = 0;
};

class RawrXDSampler {
public:
    RawrXDSampler() : cfg_{}, rng_(cfg_.seed) {}
    explicit RawrXDSampler(const SamplerConfig& c)
        : cfg_(c), rng_(c.seed) {}

    // --- configuration, settable field-wise by the adapter ---
    float    temperature = 0.0f;
    float    top_p        = 1.0f;
    int      top_k        = 0;
    float    min_p        = 0.0f;
    float    repetition_penalty = 1.0f;

    SamplerConfig config() const {
        SamplerConfig c = cfg_;
        c.temperature = temperature;
        c.top_p = top_p;
        c.top_k = top_k;
        c.min_p = min_p;
        c.repetition_penalty = repetition_penalty;
        return c;
    }

    void configure(const SamplerConfig& c) {
        cfg_ = c;
        temperature = c.temperature;
        top_p = c.top_p;
        top_k = c.top_k;
        min_p = c.min_p;
        repetition_penalty = c.repetition_penalty;
        rng_.seed(c.seed);
    }

    void reseed(uint32_t seed) { cfg_.seed = seed; rng_.seed(seed); }

    // Returns -1 when `n` is 0 or the whole candidate set is non-finite.
    // A non-finite logit set is refused rather than reduced: softmax over NaN
    // yields NaN, and returning a token from that would be a fabricated sample.
    //
    // `history` is optional; when supplied and repetition_penalty != 1.0 it is
    // used to penalise already-emitted tokens.
    uint32_t Sample(float* logits, int n,
                    const std::vector<uint32_t>& history = {}) {
        if (!logits || n <= 0) return kInvalid;

        std::vector<double> work(static_cast<size_t>(n));
        bool anyFinite = false;
        for (int i = 0; i < n; ++i) {
            const double v = static_cast<double>(logits[i]);
            work[static_cast<size_t>(i)] = (v == v && v * 0.0 == 0.0) ? v : -1e300;
            if (work[static_cast<size_t>(i)] > -1e299) anyFinite = true;
        }
        if (!anyFinite) return kInvalid;

        if (repetition_penalty != 1.0f && !history.empty()) {
            for (uint32_t t : history) {
                if (t < static_cast<uint32_t>(n)) {
                    double& v = work[t];
                    v = (v > 0.0) ? (v / repetition_penalty) : (v * repetition_penalty);
                }
            }
        }

        // Greedy: the deterministic path, and the one every gate that compares
        // token sequences depends on.
        if (temperature <= 0.0f) {
            int best = 0;
            for (int i = 1; i < n; ++i) {
                if (work[static_cast<size_t>(i)] > work[static_cast<size_t>(best)]) best = i;
            }
            return static_cast<uint32_t>(best);
        }

        // softmax with a max subtraction so exp() cannot overflow
        double maxv = work[0];
        for (int i = 1; i < n; ++i) {
            if (work[static_cast<size_t>(i)] > maxv) maxv = work[static_cast<size_t>(i)];
        }
        std::vector<double> p(static_cast<size_t>(n));
        double sum = 0.0;
        for (int i = 0; i < n; ++i) {
            const double e = std::exp((work[static_cast<size_t>(i)] - maxv) / temperature);
            p[static_cast<size_t>(i)] = e;
            sum += e;
        }
        if (!(sum > 0.0)) return kInvalid;
        for (double& v : p) v /= sum;

        // top-k
        if (top_k > 0 && top_k < n) {
            std::vector<int> idx(static_cast<size_t>(n));
            for (int i = 0; i < n; ++i) idx[static_cast<size_t>(i)] = i;
            const int k = top_k;
            std::partial_sort(idx.begin(), idx.begin() + k, idx.end(),
                [&p](int a, int b) { return p[static_cast<size_t>(a)] > p[static_cast<size_t>(b)]; });
            std::vector<double> q(static_cast<size_t>(k), 0.0);
            double qsum = 0.0;
            for (int i = 0; i < k; ++i) { q[static_cast<size_t>(i)] = p[static_cast<size_t>(idx[static_cast<size_t>(i)])]; qsum += q[static_cast<size_t>(i)]; }
            if (!(qsum > 0.0)) return kInvalid;
            for (double& v : q) v /= qsum;
            return sampleFrom(q, k);
        }

        // nucleus
        if (top_p > 0.0f && top_p < 1.0f) {
            std::vector<int> idx(static_cast<size_t>(n));
            for (int i = 0; i < n; ++i) idx[static_cast<size_t>(i)] = i;
            std::sort(idx.begin(), idx.end(),
                [&p](int a, int b) { return p[static_cast<size_t>(a)] > p[static_cast<size_t>(b)]; });
            std::vector<double> q;
            double cum = 0.0;
            for (int i = 0; i < n; ++i) {
                cum += p[static_cast<size_t>(idx[static_cast<size_t>(i)])];
                q.push_back(p[static_cast<size_t>(idx[static_cast<size_t>(i)])]);
                if (cum >= top_p) break;
            }
            double qsum = 0.0;
            for (double v : q) qsum += v;
            if (!(qsum > 0.0)) return kInvalid;
            for (double& v : q) v /= qsum;
            return static_cast<uint32_t>(idx[static_cast<size_t>(sampleFrom(q, static_cast<int>(q.size())))]);
        }

        return sampleFrom(p, n);
    }

    static constexpr uint32_t kInvalid = 0xFFFFFFFFu;

private:
    uint32_t sampleFrom(const std::vector<double>& p, int n) {
        std::uniform_real_distribution<double> u(0.0, 1.0);
        const double r = u(rng_);
        double cum = 0.0;
        for (int i = 0; i < n; ++i) {
            cum += p[static_cast<size_t>(i)];
            if (r <= cum) return static_cast<uint32_t>(i);
        }
        return static_cast<uint32_t>(n - 1);
    }

    SamplerConfig        cfg_;
    std::mt19937         rng_;
};

}  // namespace RawrXD