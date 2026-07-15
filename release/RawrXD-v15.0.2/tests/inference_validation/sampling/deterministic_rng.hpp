#pragma once

#include <cstdint>

namespace rawrxd {
namespace validation {

/**
 * Deterministic RNG for reproducible sampling
 * Uses PCG32 algorithm for high-quality random numbers
 */
class DeterministicRNG {
public:
    explicit DeterministicRNG(uint64_t seed = 42ULL)
        : state_(seed) {}
    
    void seed(uint64_t seed) {
        state_ = seed;
    }
    
    /**
     * Generate next random number
     * PCG32: state = state * multiplier + increment
     */
    uint32_t next() {
        // PCG constants
        const uint64_t multiplier = 6364136223846793005ULL;
        const uint64_t increment = 1442695040888963407ULL;
        
        uint64_t old_state = state_;
        state_ = old_state * multiplier + increment;
        
        // XSH-RR: XOR shift, random rotation
        uint32_t xorshifted = (uint32_t)(((old_state >> 18u) ^ old_state) >> 27u);
        uint32_t rot = (uint32_t)(old_state >> 59u);
        
        return (xorshifted >> rot) | (xorshifted <> ((-rot) & 31));
    }
    
    /**
     * Generate float in [0, 1)
     */
    float nextFloat() {
        return next() / 4294967296.0f; // 2^32
    }
    
    /**
     * Sample from categorical distribution
     * @param probs Probability distribution (must sum to 1)
     * @param size Size of distribution
     * @return Sampled index
     */
    int sampleCategorical(const float* probs, size_t size);
    
    /**
     * Greedy sampling (argmax) - for temperature=0
     */
    static int greedySample(const float* logits, size_t size);

private:
    uint64_t state_;
};

} // namespace validation
} // namespace rawrxd
