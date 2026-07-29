//============================================================================
// test_data_utils.hpp
// RawrXD N-EVM - Test Data Utilities
//============================================================================

#pragma once

#include <vector>
#include <random>
#include <chrono>
#include <cmath>

namespace RawrXD {
namespace NEVM {
namespace TestUtils {

//============================================================================
// Random Data Generators
//============================================================================

class RandomGenerator {
public:
    RandomGenerator(uint32_t seed = 42) : rng_(seed) {}
    
    // Generate random float vector
    std::vector<float> GenerateFloats(size_t count, float min = -1.0f, float max = 1.0f) {
        std::uniform_real_distribution<float> dist(min, max);
        std::vector<float> result(count);
        for (size_t i = 0; i < count; ++i) {
            result[i] = dist(rng_);
        }
        return result;
    }
    
    // Generate random int vector
    std::vector<int> GenerateInts(size_t count, int min = 0, int max = 100) {
        std::uniform_int_distribution<int> dist(min, max);
        std::vector<int> result(count);
        for (size_t i = 0; i < count; ++i) {
            result[i] = dist(rng_);
        }
        return result;
    }
    
    // Generate random bytes
    std::vector<uint8_t> GenerateBytes(size_t count) {
        std::uniform_int_distribution<int> dist(0, 255);
        std::vector<uint8_t> result(count);
        for (size_t i = 0; i < count; ++i) {
            result[i] = static_cast<uint8_t>(dist(rng_));
        }
        return result;
    }
    
    // Generate Gaussian distributed floats
    std::vector<float> GenerateGaussian(size_t count, float mean = 0.0f, float stddev = 1.0f) {
        std::normal_distribution<float> dist(mean, stddev);
        std::vector<float> result(count);
        for (size_t i = 0; i < count; ++i) {
            result[i] = dist(rng_);
        }
        return result;
    }
    
    // Reset with new seed
    void Reseed(uint32_t seed) {
        rng_.seed(seed);
    }
    
private:
    std::mt19937 rng_;
};

//============================================================================
// Test Data Fixtures
//============================================================================

class TestFixtures {
public:
    // Small matrix for quick tests
    static std::vector<float> SmallMatrix(size_t rows, size_t cols) {
        std::vector<float> matrix(rows * cols);
        for (size_t i = 0; i < rows * cols; ++i) {
            matrix[i] = static_cast<float>(i) * 0.01f;
        }
        return matrix;
    }
    
    // Identity matrix
    static std::vector<float> IdentityMatrix(size_t n) {
        std::vector<float> matrix(n * n, 0.0f);
        for (size_t i = 0; i < n; ++i) {
            matrix[i * n + i] = 1.0f;
        }
        return matrix;
    }
    
    // Sequential data
    static std::vector<float> Sequential(size_t count, float start = 0.0f, float step = 1.0f) {
        std::vector<float> result(count);
        for (size_t i = 0; i < count; ++i) {
            result[i] = start + static_cast<float>(i) * step;
        }
        return result;
    }
    
    // Constant values
    static std::vector<float> Constant(size_t count, float value) {
        return std::vector<float>(count, value);
    }
    
    // Token sequence (simulating LLM output)
    static std::vector<int> TokenSequence(size_t length, int vocab_size = 32000) {
        RandomGenerator rng(12345);
        return rng.GenerateInts(length, 1, vocab_size - 1);
    }
    
    // KV cache data
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> KVData(
        size_t seq_len, size_t head_dim) {
        RandomGenerator rng(54321);
        size_t k_size = seq_len * head_dim * sizeof(float);
        size_t v_size = seq_len * head_dim * sizeof(float);
        return {rng.GenerateBytes(k_size), rng.GenerateBytes(v_size)};
    }
};

//============================================================================
// Performance Measurement
//============================================================================

class Timer {
public:
    Timer() : start_(Now()) {}
    
    void Reset() {
        start_ = Now();
    }
    
    double ElapsedMs() const {
        auto end = Now();
        return std::chrono::duration<double, std::milli>(end - start_).count();
    }
    
    double ElapsedUs() const {
        auto end = Now();
        return std::chrono::duration<double, std::micro>(end - start_).count();
    }
    
private:
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = std::chrono::time_point<Clock>;
    
    static TimePoint Now() {
        return Clock::now();
    }
    
    TimePoint start_;
};

//============================================================================
// Comparison Utilities
//============================================================================

class Comparison {
public:
    static bool Near(float a, float b, float epsilon = 1e-5f) {
        return std::abs(a - b) < epsilon;
    }
    
    static bool NearRelative(float a, float b, float epsilon = 1e-5f) {
        float diff = std::abs(a - b);
        float max_val = std::max(std::abs(a), std::abs(b));
        return diff < epsilon * max_val;
    }
    
    static bool ArraysEqual(const float* a, const float* b, size_t n, float epsilon = 1e-5f) {
        for (size_t i = 0; i < n; ++i) {
            if (!Near(a[i], b[i], epsilon)) {
                return false;
            }
        }
        return true;
    }
    
    static float MaxDifference(const float* a, const float* b, size_t n) {
        float max_diff = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            max_diff = std::max(max_diff, std::abs(a[i] - b[i]));
        }
        return max_diff;
    }
    
    static float MeanSquaredError(const float* a, const float* b, size_t n) {
        float mse = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            float diff = a[i] - b[i];
            mse += diff * diff;
        }
        return mse / static_cast<float>(n);
    }
};

//============================================================================
// Mock Objects
//============================================================================

// Mock model weights
struct MockModelWeights {
    std::vector<float> embeddings;
    std::vector<float> attention_q;
    std::vector<float> attention_k;
    std::vector<float> attention_v;
    std::vector<float> attention_o;
    std::vector<float> ffn_up;
    std::vector<float> ffn_down;
    std::vector<float> output;
    
    static MockModelWeights Create(size_t vocab_size = 32000, 
                                    size_t hidden_size = 4096,
                                    size_t num_layers = 32) {
        MockModelWeights weights;
        RandomGenerator rng(99999);
        
        weights.embeddings = rng.GenerateFloats(vocab_size * hidden_size, -0.1f, 0.1f);
        weights.attention_q = rng.GenerateFloats(hidden_size * hidden_size, -0.1f, 0.1f);
        weights.attention_k = rng.GenerateFloats(hidden_size * hidden_size, -0.1f, 0.1f);
        weights.attention_v = rng.GenerateFloats(hidden_size * hidden_size, -0.1f, 0.1f);
        weights.attention_o = rng.GenerateFloats(hidden_size * hidden_size, -0.1f, 0.1f);
        weights.ffn_up = rng.GenerateFloats(hidden_size * 4 * hidden_size, -0.1f, 0.1f);
        weights.ffn_down = rng.GenerateFloats(4 * hidden_size * hidden_size, -0.1f, 0.1f);
        weights.output = rng.GenerateFloats(hidden_size * vocab_size, -0.1f, 0.1f);
        
        return weights;
    }
};

// Mock inference context
struct MockInferenceContext {
    std::vector<int> input_tokens;
    std::vector<float> logits;
    size_t seq_length = 0;
    size_t max_length = 2048;
    
    void AddToken(int token) {
        input_tokens.push_back(token);
        ++seq_length;
    }
    
    void GenerateLogits(size_t vocab_size) {
        RandomGenerator rng(88888);
        logits = rng.GenerateFloats(vocab_size, -10.0f, 10.0f);
    }
};

// Mock KV cache
struct MockKVCache {
    std::vector<std::vector<float>> k_cache;
    std::vector<std::vector<float>> v_cache;
    size_t num_layers = 0;
    size_t num_heads = 0;
    size_t head_dim = 0;
    
    static MockKVCache Create(size_t layers, size_t heads, size_t dim, size_t max_seq) {
        MockKVCache cache;
        cache.num_layers = layers;
        cache.num_heads = heads;
        cache.head_dim = dim;
        
        cache.k_cache.resize(layers);
        cache.v_cache.resize(layers);
        
        for (size_t i = 0; i < layers; ++i) {
            cache.k_cache[i].resize(heads * max_seq * dim);
            cache.v_cache[i].resize(heads * max_seq * dim);
        }
        
        return cache;
    }
};

} // namespace TestUtils
} // namespace NEVM
} // namespace RawrXD
