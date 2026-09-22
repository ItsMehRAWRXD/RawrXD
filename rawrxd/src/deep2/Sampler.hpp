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

} // namespace sampling
} // namespace rawrxd
