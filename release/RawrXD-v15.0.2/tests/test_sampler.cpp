#include <gtest/gtest.h>
#include "rawrxd/inference/Sampler.hpp"
#include "rawrxd/core/Tensor.hpp"
#include <cmath>
#include <map>

using namespace rawrxd::inference;
using namespace rawrxd::core;

class SamplerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Common setup
    }
    
    void TearDown() override {
        // Cleanup
    }
    
    // Helper to create logits tensor
    Tensor<float> CreateLogits(const std::vector<float>& values) {
        std::vector<size_t> shape = {1, values.size()};
        Tensor<float> logits(shape, DataType::FLOAT32);
        for (size_t i = 0; i < values.size(); ++i) {
            logits.At(0, i) = values[i];
        }
        return logits;
    }
};

TEST_F(SamplerTest, GreedySampling) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::GREEDY;
    
    Sampler sampler(config);
    
    // Create logits where token 3 has highest value
    std::vector<float> logits = {1.0f, 2.0f, 3.0f, 10.0f, 4.0f};
    auto logitsTensor = CreateLogits(logits);
    
    // Sample
    SamplingResult result = sampler.Sample(logitsTensor, /*seed=*/42);
    
    // Should select token with highest logit
    EXPECT_EQ(result.tokenId, 3);
}

TEST_F(SamplerTest, TemperatureSampling) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::TEMPERATURE;
    config.temperature = 1.0f;
    
    Sampler sampler(config);
    
    std::vector<float> logits = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    auto logitsTensor = CreateLogits(logits);
    
    // Sample multiple times
    std::map<int, int> tokenCounts;
    const int numSamples = 1000;
    
    for (int i = 0; i < numSamples; ++i) {
        SamplingResult result = sampler.Sample(logitsTensor, /*seed=*/i);
        tokenCounts[result.tokenId]++;
    }
    
    // Higher logits should be sampled more frequently
    EXPECT_GT(tokenCounts[4], tokenCounts[0]); // Token 4 > Token 0
    EXPECT_GT(tokenCounts[3], tokenCounts[1]); // Token 3 > Token 1
}

TEST_F(SamplerTest, TopPSampling) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::TOP_P;
    config.temperature = 1.0f;
    config.topP = 0.9f;
    
    Sampler sampler(config);
    
    // Create logits with one dominant token
    std::vector<float> logits = {0.1f, 0.1f, 0.1f, 10.0f, 0.1f};
    auto logitsTensor = CreateLogits(logits);
    
    // Sample multiple times
    std::map<int, int> tokenCounts;
    const int numSamples = 100;
    
    for (int i = 0; i < numSamples; ++i) {
        SamplingResult result = sampler.Sample(logitsTensor, /*seed=*/i);
        tokenCounts[result.tokenId]++;
    }
    
    // With top_p=0.9, should mostly sample token 3
    EXPECT_GT(tokenCounts[3], numSamples * 0.8);
}

TEST_F(SamplerTest, TopKSampling) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::TOP_K;
    config.temperature = 1.0f;
    config.topK = 2;
    
    Sampler sampler(config);
    
    // Create logits
    std::vector<float> logits = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    auto logitsTensor = CreateLogits(logits);
    
    // Sample multiple times
    std::map<int, int> tokenCounts;
    const int numSamples = 100;
    
    for (int i = 0; i < numSamples; ++i) {
        SamplingResult result = sampler.Sample(logitsTensor, /*seed=*/i);
        tokenCounts[result.tokenId]++;
        
        // Should only sample from top 2 tokens (indices 3 and 4)
        EXPECT_TRUE(result.tokenId == 3 || result.tokenId == 4);
    }
}

TEST_F(SamplerTest, RepetitionPenalty) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::TEMPERATURE;
    config.temperature = 1.0f;
    config.repetitionPenalty = 2.0f;
    
    Sampler sampler(config);
    
    // Add repeated tokens to history
    std::vector<int> tokenHistory = {0, 0, 0, 1, 1}; // Token 0 appears 3 times, token 1 appears 2 times
    sampler.SetTokenHistory(tokenHistory);
    
    std::vector<float> logits = {5.0f, 5.0f, 1.0f, 1.0f, 1.0f};
    auto logitsTensor = CreateLogits(logits);
    
    // Sample multiple times
    std::map<int, int> tokenCounts;
    const int numSamples = 100;
    
    for (int i = 0; i < numSamples; ++i) {
        SamplingResult result = sampler.Sample(logitsTensor, /*seed=*/i);
        tokenCounts[result.tokenId]++;
    }
    
    // Token 0 and 1 should be penalized, so token 2, 3, 4 should be sampled more
    EXPECT_LT(tokenCounts[0], tokenCounts[2]);
    EXPECT_LT(tokenCounts[1], tokenCounts[2]);
}

TEST_F(SamplerTest, MinPSampling) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::MIN_P;
    config.temperature = 1.0f;
    config.minP = 0.05f;
    
    Sampler sampler(config);
    
    std::vector<float> logits = {10.0f, 5.0f, 1.0f, 0.1f, 0.01f};
    auto logitsTensor = CreateLogits(logits);
    
    // Sample multiple times
    std::map<int, int> tokenCounts;
    const int numSamples = 100;
    
    for (int i = 0; i < numSamples; ++i) {
        SamplingResult result = sampler.Sample(logitsTensor, /*seed=*/i);
        tokenCounts[result.tokenId]++;
    }
    
    // Very low probability tokens should rarely be sampled
    EXPECT_EQ(tokenCounts[4], 0); // Token with 0.01 logit should never be sampled
}

TEST_F(SamplerTest, TypicalSampling) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::TYPICAL;
    config.temperature = 1.0f;
    config.typicalP = 0.9f;
    
    Sampler sampler(config);
    
    std::vector<float> logits = {2.0f, 2.0f, 2.0f, 2.0f, 10.0f};
    auto logitsTensor = CreateLogits(logits);
    
    // Sample
    SamplingResult result = sampler.Sample(logitsTensor, /*seed=*/42);
    
    // Should return valid token
    EXPECT_GE(result.tokenId, 0);
    EXPECT_LT(result.tokenId, 5);
}

TEST_F(SamplerTest, MirostatSampling) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::MIROSTAT;
    config.mirostatTau = 5.0f;
    config.mirostatEta = 0.1f;
    
    Sampler sampler(config);
    
    std::vector<float> logits(1000);
    for (size_t i = 0; i < logits.size(); ++i) {
        logits[i] = static_cast<float>(i) * 0.01f;
    }
    auto logitsTensor = CreateLogits(logits);
    
    // Sample multiple tokens
    std::vector<int> tokens;
    for (int i = 0; i < 10; ++i) {
        SamplingResult result = sampler.Sample(logitsTensor, /*seed=*/i);
        tokens.push_back(result.tokenId);
        sampler.AddTokenToHistory(result.tokenId);
    }
    
    // Should have generated 10 tokens
    EXPECT_EQ(tokens.size(), 10);
}

TEST_F(SamplerTest, BeamSearch) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::BEAM_SEARCH;
    config.beamWidth = 3;
    config.maxLength = 10;
    
    Sampler sampler(config);
    
    // Initial logits
    std::vector<float> logits = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    auto logitsTensor = CreateLogits(logits);
    
    // Initialize beam search
    sampler.InitializeBeamSearch(logitsTensor);
    
    // Run a few steps
    for (int step = 0; step < 5; ++step) {
        // Create new logits for each beam
        std::vector<Tensor<float>> beamLogits;
        for (int b = 0; b < config.beamWidth; ++b) {
            std::vector<float> newLogits = {
                static_cast<float>(step + b),
                static_cast<float>(step + b + 1),
                static_cast<float>(step + b + 2),
                static_cast<float>(step + b + 3),
                static_cast<float>(step + b + 4)
            };
            beamLogits.push_back(CreateLogits(newLogits));
        }
        
        sampler.BeamSearchStep(beamLogits);
    }
    
    // Get best sequence
    auto bestSequence = sampler.GetBestBeam();
    EXPECT_FALSE(bestSequence.empty());
}

TEST_F(SamplerTest, ContrastiveSearch) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::CONTRASTIVE;
    config.contrastiveAlpha = 0.5f;
    config.topK = 5;
    
    Sampler sampler(config);
    
    std::vector<float> logits = {5.0f, 4.0f, 3.0f, 2.0f, 1.0f};
    auto logitsTensor = CreateLogits(logits);
    
    // Previous hidden states (mock)
    std::vector<size_t> hiddenShape = {5, 64};
    Tensor<float> prevHidden(hiddenShape, DataType::FLOAT32);
    prevHidden.RandomNormal(0.0f, 0.1f, 42);
    
    // Current hidden states (mock)
    Tensor<float> currHidden(hiddenShape, DataType::FLOAT32);
    currHidden.RandomNormal(0.0f, 0.1f, 43);
    
    // Sample with contrastive search
    SamplingResult result = sampler.ContrastiveSearch(
        logitsTensor, prevHidden, currHidden, /*seed=*/42);
    
    // Should return valid token
    EXPECT_GE(result.tokenId, 0);
    EXPECT_LT(result.tokenId, 5);
}

TEST_F(SamplerTest, TemperatureScaling) {
    // Test that temperature affects distribution
    std::vector<float> logits = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    
    // High temperature = more uniform
    SamplerConfig configHigh;
    configHigh.strategy = SamplingStrategy::TEMPERATURE;
    configHigh.temperature = 10.0f;
    Sampler samplerHigh(configHigh);
    
    // Low temperature = more peaked
    SamplerConfig configLow;
    configLow.strategy = SamplingStrategy::TEMPERATURE;
    configLow.temperature = 0.1f;
    Sampler samplerLow(configLow);
    
    auto logitsTensor = CreateLogits(logits);
    
    // Sample with high temperature
    std::map<int, int> countsHigh;
    for (int i = 0; i < 100; ++i) {
        auto result = samplerHigh.Sample(logitsTensor, i);
        countsHigh[result.tokenId]++;
    }
    
    // Sample with low temperature
    std::map<int, int> countsLow;
    for (int i = 0; i < 100; ++i) {
        auto result = samplerLow.Sample(logitsTensor, i);
        countsLow[result.tokenId]++;
    }
    
    // Low temperature should be more concentrated on high-probability tokens
    float entropyHigh = 0.0f, entropyLow = 0.0f;
    for (int i = 0; i < 5; ++i) {
        float pHigh = countsHigh[i] / 100.0f;
        float pLow = countsLow[i] / 100.0f;
        if (pHigh > 0) entropyHigh -= pHigh * std::log(pHigh);
        if (pLow > 0) entropyLow -= pLow * std::log(pLow);
    }
    
    EXPECT_GT(entropyHigh, entropyLow);
}

TEST_F(SamplerTest, SeedReproducibility) {
    SamplerConfig config;
    config.strategy = SamplingStrategy::TEMPERATURE;
    config.temperature = 1.0f;
    
    Sampler sampler(config);
    
    std::vector<float> logits = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    auto logitsTensor = CreateLogits(logits);
    
    // Sample with same seed twice
    auto result1 = sampler.Sample(logitsTensor, /*seed=*/42);
    auto result2 = sampler.Sample(logitsTensor, /*seed=*/42);
    
    // Should get same result
    EXPECT_EQ(result1.tokenId, result2.tokenId);
    EXPECT_FLOAT_EQ(result1.logProb, result2.logProb);
}
