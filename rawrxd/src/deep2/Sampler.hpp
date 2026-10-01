#pragma once
/* Sampler — greedy argmax, temperature, top-k, top-p */
#include <vector>
#include <cstdint>
#include <functional>

namespace rawrxd {
namespace sampling {

struct ISampler {
    virtual ~ISampler() = default;
    virtual int sample(const float* logits, int n_vocab) = 0;
};

class GreedySampler : public ISampler {
public:
    int sample(const float* logits, int n_vocab) override;
};

class TemperatureSampler : public ISampler {
public:
    explicit TemperatureSampler(float temp = 0.8f) : temp_(temp) {}
    int sample(const float* logits, int n_vocab) override;
private:
    float temp_;
};

class TopKSampler : public ISampler {
public:
    TopKSampler(int k = 40, float temp = 0.8f) : k_(k), temp_(temp) {}
    int sample(const float* logits, int n_vocab) override;
private:
    int k_;
    float temp_;
};

// ============================================================================
// RAWRXD_BATCH_02_SAMPLER_GATE_001 — additional samplers required so that
// every GenerationOptions field has a real consumer.
//
// topP    -> TopPSampler / CombinedSampler
// minP    -> MinPSampler / CombinedSampler
// repeatPenalty -> RepetitionPenaltyProcessor (decorates any sampler)
// seed    -> Consumed only by stochastic samplers. The existing deterministic
//            samplers (Greedy, Temperature, TopK in this file) are
//            softmax+argmax and have no stochastic draw; CombinedSampler with
//            topP > 0 OR minP > 0 IS stochastic and consumes seed.
// ============================================================================

class TopPSampler : public ISampler {
public:
    TopPSampler(float p = 0.95f, float temp = 1.0f, uint64_t seed = 0)
        : p_(p), temp_(temp), rng_state_(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    int sample(const float* logits, int n_vocab) override;
private:
    float p_;
    float temp_;
    uint64_t rng_state_;
    uint64_t nextRand() { rng_state_ ^= rng_state_ << 13; rng_state_ ^= rng_state_ >> 7; rng_state_ ^= rng_state_ << 17; return rng_state_; }
};

class MinPSampler : public ISampler {
public:
    MinPSampler(float minP = 0.05f, float temp = 1.0f, uint64_t seed = 0)
        : minP_(minP), temp_(temp), rng_state_(seed ? seed : 0xC6BC279692B5C323ULL) {}
    int sample(const float* logits, int n_vocab) override;
private:
    float minP_;
    float temp_;
    uint64_t rng_state_;
    uint64_t nextRand() { rng_state_ ^= rng_state_ << 13; rng_state_ ^= rng_state_ >> 7; rng_state_ ^= rng_state_ << 17; return rng_state_; }
};

// Decorates any sampler by applying a repetition penalty to logits of any
// token present in `priorTokens` before delegating to the inner sampler.
class RepetitionPenaltyProcessor {
public:
    explicit RepetitionPenaltyProcessor(float penalty = 1.0f) : penalty_(penalty) {}
    // Returns true if `penalty_` was applied (i.e. > 1.0f effectively).
    bool active() const { return penalty_ > 1.0f + 1e-6f; }
    void apply(float* logits, int n_vocab, const int* priorTokens, int nPrior) const;
    float penalty() const { return penalty_; }
private:
    float penalty_;
};

// CombinedSampler: topK -> topP -> minP -> temperature -> categorical draw.
// Consumes topK + topP + minP + temperature + seed. Decorated externally with
// RepetitionPenaltyProcessor when repeatPenalty > 1.0f.
class CombinedSampler : public ISampler {
public:
    CombinedSampler(uint32_t topK, float topP, float minP, float temp, uint64_t seed)
        : topK_(topK), topP_(topP), minP_(minP), temp_(temp),
          rng_state_(seed ? seed : 0xD1342543DE82EF95ULL) {}
    int sample(const float* logits, int n_vocab) override;
private:
    uint32_t topK_;
    float topP_;
    float minP_;
    float temp_;
    uint64_t rng_state_;
    uint64_t nextRand() { rng_state_ ^= rng_state_ << 13; rng_state_ ^= rng_state_ >> 7; rng_state_ ^= rng_state_ << 17; return rng_state_; }
};

} // namespace sampling
} // namespace rawrxd
