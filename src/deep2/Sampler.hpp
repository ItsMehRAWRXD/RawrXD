// ============================================================================
// Sampler.hpp — Advanced sampling header (stub)
// ============================================================================
#pragma once

#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace rawrxd {
namespace sampling {

class ISampler {
public:
    virtual ~ISampler() = default;
    [[nodiscard]] virtual int32_t sample(const std::vector<float>& logits) = 0;
    [[nodiscard]] virtual uint32_t vocabSize() const = 0;
    [[nodiscard]] virtual bool initialized() const = 0;
};

class AdvancedSampler : public ISampler {
public:
    AdvancedSampler();
    ~AdvancedSampler() = default;

    [[nodiscard]] uint32_t vocabSize() const override { return vocab_size_; }
    void setVocabSize(uint32_t vocabSize) { vocab_size_ = vocabSize; }

    [[nodiscard]] bool initialized() const override { return initialized_; }
    void setInitialized(bool initialized) { initialized_ = initialized; }

    // Sample a token from logits
    [[nodiscard]] int32_t sample(const std::vector<float>& logits) override;

    // Sample with temperature
    [[nodiscard]] int32_t sampleWithTemperature(const std::vector<float>& logits, float temperature);

    // Sample with top-k filtering
    [[nodiscard]] int32_t sampleTopK(const std::vector<float>& logits, int32_t k);

    // Sample with top-p (nucleus) filtering
    [[nodiscard]] int32_t sampleTopP(const std::vector<float>& logits, float p);

protected:
    uint32_t vocab_size_ = 0;
    std::mt19937 rng_{std::random_device{}()};
    bool initialized_ = false;
};

} // namespace sampling
} // namespace rawrxd
