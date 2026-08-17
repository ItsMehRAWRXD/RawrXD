#pragma once

//==============================================================================
// advanced_sampler.hpp - Deep2 Advanced Sampling
// Phase 15B: Real Executable Build
//
// Wraps the RawrXD sampling infrastructure for Deep2
//==============================================================================

#include <vector>
#include <cstdint>
#include <random>
#include <memory>

namespace Deep2 {

// SamplingConfig is defined in Deep2Engine.h - using that definition

//==============================================================================
// AdvancedSampler - Token sampling with advanced techniques
//==============================================================================
class AdvancedSampler {
public:
    AdvancedSampler();
    ~AdvancedSampler();
    
    // Configuration
    void Configure(float temperature, float topP, int topK);
    void SetRepetitionPenalty(float penalty);
    
    // Sample from logits
    int Sample(const std::vector<float>& logits);
    int SampleWithPenalty(const std::vector<float>& logits, const std::vector<int>& previousTokens);
    
    // Get last sampling info
    float GetLastProbability() const;
    float GetLastEntropy() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace Deep2
