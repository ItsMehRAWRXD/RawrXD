// ============================================================================
// C5d: Speculative Decoding
// Draft model generates K tokens, target model verifies in parallel
// 1.5x speedup over baseline (target: ~200 tok/s)
// ============================================================================

#pragma once

#include <vector>
#include <cstdint>
#include <memory>
#include <functional>

namespace benchmark {

// ============================================================================
// Speculative Decoding Configuration
// ============================================================================

struct SpeculativeConfig {
    int maxDraftTokens = 4;           // K: number of tokens to draft
    float temperature = 0.8f;       // Sampling temperature
    float acceptanceThreshold = 0.9f; // Min probability to accept draft token
    bool useStrictValidation = true;  // Validate all K tokens or reject
    
    // Performance tuning
    int draftModelLayers = 4;       // Small draft model (4 vs 34 layers)
    int targetModelLayers = 34;     // Full target model
};

// ============================================================================
// Token Acceptance Result
// ============================================================================

struct AcceptanceResult {
    int acceptedCount = 0;            // Number of accepted tokens (0 to K)
    std::vector<uint32_t> tokens;     // Accepted token IDs
    float acceptanceRate = 0.0f;      // acceptedCount / K
    bool allAccepted = false;         // true if acceptedCount == K
};

// ============================================================================
// Draft Model Interface
// ============================================================================

class IDraftModel {
public:
    virtual ~IDraftModel() = default;
    
    // Generate K draft tokens
    virtual std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& prompt,
        int numTokens,
        float temperature
    ) = 0;
    
    // Get draft model latency (for telemetry)
    virtual float GetDraftLatencyMs() const = 0;
};

// ============================================================================
// Target Model Interface
// ============================================================================

class ITargetModel {
public:
    virtual ~ITargetModel() = default;
    
    // Verify K draft tokens in parallel
    // Returns logits for all positions
    virtual std::vector<std::vector<float>> VerifyDraft(
        const std::vector<uint32_t>& prompt,
        const std::vector<uint32_t>& draftTokens
    ) = 0;
    
    // Get target model latency (for telemetry)
    virtual float GetTargetLatencyMs() const = 0;
};

// ============================================================================
// Speculative Decoder
// ============================================================================

class SpeculativeDecoder {
public:
    SpeculativeDecoder();
    ~SpeculativeDecoder();
    
    // Initialize with draft and target models
    bool Initialize(
        std::unique_ptr<IDraftModel> draftModel,
        std::unique_ptr<ITargetModel> targetModel,
        const SpeculativeConfig& config
    );
    
    // Generate tokens with speculative decoding
    std::vector<uint32_t> Generate(
        const std::vector<uint32_t>& prompt,
        int maxTokens,
        std::function<void(uint32_t)> onToken = nullptr
    );
    
    // Get performance statistics
    struct Stats {
        int totalTokensGenerated = 0;
        int totalDraftTokens = 0;
        int totalAcceptedTokens = 0;
        float acceptanceRate = 0.0f;
        float avgTokensPerStep = 0.0f;
        float speedupVsBaseline = 1.0f;
        float draftLatencyMs = 0.0f;
        float targetLatencyMs = 0.0f;
    };
    Stats GetStats() const;
    
    // Reset statistics
    void ResetStats();
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Mock Implementations (for testing)
// ============================================================================

class MockDraftModel : public IDraftModel {
public:
    MockDraftModel(float latencyMs = 5.0f);
    
    std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& prompt,
        int numTokens,
        float temperature
    ) override;
    
    float GetDraftLatencyMs() const override;
    
    // Configure mock behavior
    void SetAcceptanceRate(float rate);  // 0.0 to 1.0
    
private:
    float latencyMs_;
    float acceptanceRate_ = 0.8f;
};

class MockTargetModel : public ITargetModel {
public:
    MockTargetModel(float latencyMs = 50.0f);
    
    std::vector<std::vector<float>> VerifyDraft(
        const std::vector<uint32_t>& prompt,
        const std::vector<uint32_t>& draftTokens
    ) override;
    
    float GetTargetLatencyMs() const override;
    
private:
    float latencyMs_;
};

// ============================================================================
// Benchmark
// ============================================================================

struct SpeculativeBenchmarkResult {
    float tokensPerSecond;
    float acceptanceRate;
    float speedupVsBaseline;
    float avgTokensPerStep;
    int totalTokens;
    int totalSteps;
};

SpeculativeBenchmarkResult BenchmarkSpeculativeDecoding(
    int maxTokens = 100,
    const SpeculativeConfig& config = {}
);

} // namespace benchmark
