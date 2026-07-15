// ============================================================================
// C5d: Speculative Decoding - Implementation
// ============================================================================

#include "speculative_decoder.hpp"
#include <random>
#include <chrono>
#include <thread>
#include <algorithm>

namespace benchmark {

// ============================================================================
// Mock Draft Model
// ============================================================================

MockDraftModel::MockDraftModel(float latencyMs) : latencyMs_(latencyMs) {}

std::vector<uint32_t> MockDraftModel::GenerateDraft(
    const std::vector<uint32_t>& prompt,
    int numTokens,
    float temperature) {
    
    // Simulate latency
    std::this_thread::sleep_for(std::chrono::microseconds(static_cast<int>(latencyMs_ * 1000)));
    
    // Generate deterministic draft tokens based on prompt
    std::vector<uint32_t> draft;
    uint32_t seed = prompt.empty() ? 42 : prompt.back();
    
    for (int i = 0; i < numTokens; i++) {
        // Simple hash for deterministic output
        seed = seed * 1103515245 + 12345;
        draft.push_back(1000 + (seed % 1000));  // Token IDs 1000-1999
    }
    
    return draft;
}

float MockDraftModel::GetDraftLatencyMs() const {
    return latencyMs_;
}

void MockDraftModel::SetAcceptanceRate(float rate) {
    acceptanceRate_ = std::max(0.0f, std::min(1.0f, rate));
}

// ============================================================================
// Mock Target Model
// ============================================================================

MockTargetModel::MockTargetModel(float latencyMs) : latencyMs_(latencyMs) {}

std::vector<std::vector<float>> MockTargetModel::VerifyDraft(
    const std::vector<uint32_t>& prompt,
    const std::vector<uint32_t>& draftTokens) {
    
    // Simulate latency (parallel verification - same time regardless of K)
    std::this_thread::sleep_for(std::chrono::microseconds(static_cast<int>(latencyMs_ * 1000)));
    
    // Generate logits for each position
    std::vector<std::vector<float>> logits;
    uint32_t seed = prompt.empty() ? 42 : prompt.back();
    
    for (size_t i = 0; i < draftTokens.size(); i++) {
        std::vector<float> positionLogits(32000);  // Vocab size
        
        // Fill with random values
        for (float& logit : positionLogits) {
            seed = seed * 1103515245 + 12345;
            logit = static_cast<float>(seed % 100) / 10.0f - 5.0f;
        }
        
        // Make the draft token somewhat likely (for acceptance)
        if (draftTokens[i] < positionLogits.size()) {
            positionLogits[draftTokens[i]] = 2.0f;  // Higher logit = more likely
        }
        
        logits.push_back(positionLogits);
    }
    
    return logits;
}

float MockTargetModel::GetTargetLatencyMs() const {
    return latencyMs_;
}

// ============================================================================
// Speculative Decoder Implementation
// ============================================================================

class SpeculativeDecoder::Impl {
public:
    std::unique_ptr<IDraftModel> draftModel_;
    std::unique_ptr<ITargetModel> targetModel_;
    SpeculativeConfig config_;
    
    // Statistics
    int totalTokensGenerated_ = 0;
    int totalDraftTokens_ = 0;
    int totalAcceptedTokens_ = 0;
    int totalSteps_ = 0;
    float totalDraftLatency_ = 0.0f;
    float totalTargetLatency_ = 0.0f;
    
    bool Initialize(std::unique_ptr<IDraftModel> draftModel,
                   std::unique_ptr<ITargetModel> targetModel,
                   const SpeculativeConfig& config) {
        draftModel_ = std::move(draftModel);
        targetModel_ = std::move(targetModel);
        config_ = config;
        return true;
    }
    
    std::vector<uint32_t> Generate(const std::vector<uint32_t>& prompt,
                                  int maxTokens,
                                  std::function<void(uint32_t)> onToken) {
        std::vector<uint32_t> generated;
        std::vector<uint32_t> context = prompt;
        
        auto startTime = std::chrono::high_resolution_clock::now();
        
        while (static_cast<int>(generated.size()) < maxTokens) {
            // Step 1: Draft model generates K tokens
            auto draftStart = std::chrono::high_resolution_clock::now();
            auto draftTokens = draftModel_->GenerateDraft(context, config_.maxDraftTokens, config_.temperature);
            auto draftEnd = std::chrono::high_resolution_clock::now();
            totalDraftLatency_ += std::chrono::duration<float, std::milli>(draftEnd - draftStart).count();
            
            totalDraftTokens_ += draftTokens.size();
            
            // Step 2: Target model verifies all K tokens in parallel
            auto targetStart = std::chrono::high_resolution_clock::now();
            auto logits = targetModel_->VerifyDraft(context, draftTokens);
            auto targetEnd = std::chrono::high_resolution_clock::now();
            totalTargetLatency_ += std::chrono::duration<float, std::milli>(targetEnd - targetStart).count();
            
            // Step 3: Accept/reject tokens
            int accepted = 0;
            for (size_t i = 0; i < draftTokens.size() && static_cast<int>(generated.size()) < maxTokens; i++) {
                // Simple acceptance: check if draft token is in top probabilities
                // In real implementation, would sample from distribution
                float acceptanceProb = 0.9f;  // Simulated
                
                if (acceptanceProb >= config_.acceptanceThreshold) {
                    generated.push_back(draftTokens[i]);
                    context.push_back(draftTokens[i]);
                    accepted++;
                    
                    if (onToken) {
                        onToken(draftTokens[i]);
                    }
                } else {
                    // Reject: sample new token from target distribution
                    uint32_t newToken = 1000 + (rand() % 1000);
                    generated.push_back(newToken);
                    context.push_back(newToken);
                    
                    if (onToken) {
                        onToken(newToken);
                    }
                    break;  // Stop accepting after first rejection
                }
            }
            
            totalAcceptedTokens_ += accepted;
            totalTokensGenerated_ += std::min(static_cast<int>(draftTokens.size()), 
                                              maxTokens - static_cast<int>(generated.size()));
            totalSteps_++;
            
            if (static_cast<int>(generated.size()) >= maxTokens) {
                break;
            }
        }
        
        return generated;
    }
    
    Stats GetStats() const {
        Stats stats;
        stats.totalTokensGenerated = totalTokensGenerated_;
        stats.totalDraftTokens = totalDraftTokens_;
        stats.totalAcceptedTokens = totalAcceptedTokens_;
        
        if (totalDraftTokens_ > 0) {
            stats.acceptanceRate = static_cast<float>(totalAcceptedTokens_) / totalDraftTokens_;
        }
        
        if (totalSteps_ > 0) {
            stats.avgTokensPerStep = static_cast<float>(totalTokensGenerated_) / totalSteps_;
        }
        
        // Calculate speedup
        // Baseline: target latency per token
        // Speculative: (draft latency + target latency) / avg tokens per step
        float baselineTimePerToken = targetModel_->GetTargetLatencyMs();
        float speculativeTimePerStep = draftModel_->GetDraftLatencyMs() + targetModel_->GetTargetLatencyMs();
        float speculativeTimePerToken = speculativeTimePerStep / std::max(1.0f, stats.avgTokensPerStep);
        
        if (speculativeTimePerToken > 0) {
            stats.speedupVsBaseline = baselineTimePerToken / speculativeTimePerToken;
        }
        
        stats.draftLatencyMs = totalDraftLatency_;
        stats.targetLatencyMs = totalTargetLatency_;
        
        return stats;
    }
    
    void ResetStats() {
        totalTokensGenerated_ = 0;
        totalDraftTokens_ = 0;
        totalAcceptedTokens_ = 0;
        totalSteps_ = 0;
        totalDraftLatency_ = 0.0f;
        totalTargetLatency_ = 0.0f;
    }
};

SpeculativeDecoder::SpeculativeDecoder() : pImpl(std::make_unique<Impl>()) {}
SpeculativeDecoder::~SpeculativeDecoder() = default;

bool SpeculativeDecoder::Initialize(std::unique_ptr<IDraftModel> draftModel,
                                    std::unique_ptr<ITargetModel> targetModel,
                                    const SpeculativeConfig& config) {
    return pImpl->Initialize(std::move(draftModel), std::move(targetModel), config);
}

std::vector<uint32_t> SpeculativeDecoder::Generate(const std::vector<uint32_t>& prompt,
                                                    int maxTokens,
                                                    std::function<void(uint32_t)> onToken) {
    return pImpl->Generate(prompt, maxTokens, onToken);
}

SpeculativeDecoder::Stats SpeculativeDecoder::GetStats() const {
    return pImpl->GetStats();
}

void SpeculativeDecoder::ResetStats() {
    pImpl->ResetStats();
}

// ============================================================================
// Benchmark
// ============================================================================

SpeculativeBenchmarkResult BenchmarkSpeculativeDecoding(int maxTokens,
                                                         const SpeculativeConfig& config) {
    // Create mock models
    // Draft: 5ms (10x faster than target)
    // Target: 50ms (simulates full transformer forward pass)
    auto draftModel = std::make_unique<MockDraftModel>(5.0f);
    auto targetModel = std::make_unique<MockTargetModel>(50.0f);
    
    SpeculativeDecoder decoder;
    decoder.Initialize(std::move(draftModel), std::move(targetModel), config);
    
    // Run benchmark
    std::vector<uint32_t> prompt = {100, 200, 300};  // Example prompt tokens
    
    auto start = std::chrono::high_resolution_clock::now();
    auto tokens = decoder.Generate(prompt, maxTokens);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto stats = decoder.GetStats();
    
    float elapsedMs = std::chrono::duration<float, std::milli>(end - start).count();
    float tokensPerSecond = (tokens.size() * 1000.0f) / elapsedMs;
    
    SpeculativeBenchmarkResult result;
    result.tokensPerSecond = tokensPerSecond;
    result.acceptanceRate = stats.acceptanceRate;
    result.speedupVsBaseline = stats.speedupVsBaseline;
    result.avgTokensPerStep = stats.avgTokensPerStep;
    result.totalTokens = tokens.size();
    result.totalSteps = stats.totalTokensGenerated / std::max(1.0f, stats.avgTokensPerStep);
    
    return result;
}

} // namespace benchmark
