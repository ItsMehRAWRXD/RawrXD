/*===========================================================================
 * speculative_decoder_main.cpp
 *
 * VAL-032: Speculative Decoding Main Implementation
 *
 * Main decoder with N-gram and Medusa support
 *===========================================================================*/

#include "speculative_decoder.hpp"
#include "speculative_decoder_impl.hpp"
#include <chrono>
#include <cstring>

namespace RawrXD {
namespace Inference {

// SpeculativeDecoder implementation
SpeculativeDecoder::SpeculativeDecoder() = default;

SpeculativeDecoder::~SpeculativeDecoder() = default;

bool SpeculativeDecoder::Initialize(const SpeculativeConfig& config) {
    config_ = config;
    verifier_ = std::make_unique<TreeAttentionVerifier>();
    
    // Initialize with N-gram draft model by default
    if (config.useNgramFallback) {
        draftModel_ = std::make_shared<NGramDraftModel>(config.ngramOrder);
    }
    
    return true;
}

void SpeculativeDecoder::SetDraftModel(std::shared_ptr<DraftModel> draftModel) {
    draftModel_ = draftModel;
}

void SpeculativeDecoder::SetTargetModel(TargetModelCallback callback) {
    targetModel_ = callback;
}

uint32_t SpeculativeDecoder::Generate(
    const uint32_t* contextTokens,
    uint32_t contextLength,
    uint32_t* outputTokens,
    uint32_t maxOutputTokens
) {
    if (!draftModel_ || !targetModel_) {
        // Fall back to base model
        return GenerateSingleStep(contextTokens, contextLength, outputTokens);
    }
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    uint32_t totalGenerated = 0;
    uint32_t currentContextLength = contextLength;
    
    // Temporary buffer for extended context
    std::vector<uint32_t> extendedContext(contextTokens, contextTokens + contextLength);
    
    while (totalGenerated < maxOutputTokens) {
        // Step 1: Generate draft tokens
        auto draftCandidates = draftModel_->GenerateDraft(
            extendedContext.data(),
            currentContextLength,
            config_.maxDraftTokens
        );
        
        if (draftCandidates.empty()) {
            // No draft available, fall back to base model
            uint32_t token;
            if (GenerateSingleStep(extendedContext.data(), currentContextLength, &token) == 0) {
                break;
            }
            outputTokens[totalGenerated++] = token;
            extendedContext.push_back(token);
            currentContextLength++;
            continue;
        }
        
        draftTokensGenerated_ += draftCandidates.size();
        
        // Step 2: Build verification tree
        if (config_.useTreeAttention) {
            verifier_->BuildTree(draftCandidates);
        }
        
        // Step 3: Run target model verification
        // In production, would run tree attention over all draft positions
        // Simplified: verify sequentially
        std::vector<uint32_t> draftSequence;
        for (const auto& candidate : draftCandidates) {
            draftSequence.push_back(candidate.tokenId);
        }
        
        // Extend context with draft tokens for verification
        std::vector<uint32_t> verifyContext = extendedContext;
        verifyContext.insert(verifyContext.end(), draftSequence.begin(), draftSequence.end());
        
        // Get target model logits for verification positions
        // Simplified: just verify first token
        float targetLogits[32000];  // Assuming vocab size
        std::memset(targetLogits, 0, sizeof(targetLogits));
        
        // Call target model
        targetModel_(
            verifyContext.data(),
            currentContextLength + 1,  // Verify first draft token
            targetLogits,
            32000
        );
        
        // Step 4: Acceptance sampling
        uint32_t acceptedCount = 0;
        for (uint32_t i = 0; i < draftCandidates.size() && i < 1; i++) {  // Verify 1 for now
            if (AcceptToken(draftCandidates[i].probability, 
                          targetLogits[draftCandidates[i].tokenId], 
                          config_.temperature / 1000.0f)) {
                acceptedCount++;
            } else {
                break;
            }
        }
        
        // Step 5: Output accepted tokens
        for (uint32_t i = 0; i < acceptedCount && totalGenerated < maxOutputTokens; i++) {
            outputTokens[totalGenerated++] = draftCandidates[i].tokenId;
            extendedContext.push_back(draftCandidates[i].tokenId);
            currentContextLength++;
        }
        
        tokensAccepted_ += acceptedCount;
        tokensRejected_ += (draftCandidates.size() - acceptedCount);
        
        // If no tokens accepted, generate one with base model
        if (acceptedCount == 0) {
            uint32_t token;
            if (GenerateSingleStep(extendedContext.data(), currentContextLength, &token) == 0) {
                break;
            }
            outputTokens[totalGenerated++] = token;
            extendedContext.push_back(token);
            currentContextLength++;
        }
        
        // Stop if we've generated enough
        if (totalGenerated >= maxOutputTokens) {
            break;
        }
    }
    
    auto endTime = std::chrono::high_resolution_clock::now();
    double latencyMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
    
    totalCalls_++;
    totalLatencyMs_ += latencyMs;
    
    return totalGenerated;
}

uint32_t SpeculativeDecoder::GenerateSingleStep(
    const uint32_t* contextTokens,
    uint32_t contextLength,
    uint32_t* outputToken
) {
    if (!targetModel_) {
        return 0;
    }
    
    float logits[32000];
    std::memset(logits, 0, sizeof(logits));
    
    targetModel_(contextTokens, contextLength, logits, 32000);
    
    // Greedy sampling (argmax)
    uint32_t bestToken = 0;
    float bestLogit = logits[0];
    for (uint32_t i = 1; i < 32000; i++) {
        if (logits[i] > bestLogit) {
            bestLogit = logits[i];
            bestToken = i;
        }
    }
    
    *outputToken = bestToken;
    return 1;
}

bool SpeculativeDecoder::AcceptToken(float draftProb, float targetProb, float temperature) {
    // Modified rejection sampling
    // Accept if target_prob >= draft_prob
    // Or with probability target_prob / draft_prob
    
    if (targetProb >= draftProb) {
        return true;
    }
    
    // Rejection sampling
    float acceptProb = targetProb / (draftProb * temperature);
    return (static_cast<float>(rand()) / RAND_MAX) < acceptProb;
}

SpeculativeDecoder::PerformanceStats SpeculativeDecoder::GetStats() const {
    PerformanceStats stats;
    stats.totalCalls = totalCalls_.load();
    stats.draftTokensGenerated = draftTokensGenerated_.load();
    stats.tokensAccepted = tokensAccepted_.load();
    stats.tokensRejected = tokensRejected_.load();
    
    uint64_t totalTokens = stats.tokensAccepted + stats.tokensRejected;
    if (totalTokens > 0) {
        stats.acceptanceRate = static_cast<float>(stats.tokensAccepted) / totalTokens;
    } else {
        stats.acceptanceRate = 0.0f;
    }
    
    if (stats.totalCalls > 0) {
        stats.avgTokensPerCall = static_cast<float>(stats.tokensAccepted) / stats.totalCalls;
        stats.avgLatencyMs = totalLatencyMs_.load() / stats.totalCalls;
    } else {
        stats.avgTokensPerCall = 0.0f;
        stats.avgLatencyMs = 0.0;
    }
    
    // Speedup calculation
    // Base model: 1 token per call
    // Speculative: avgTokensPerCall tokens per call
    if (stats.avgTokensPerCall > 0) {
        stats.speedupVsBase = stats.avgTokensPerCall;
    } else {
        stats.speedupVsBase = 1.0;
    }
    
    return stats;
}

void SpeculativeDecoder::ResetStats() {
    totalCalls_ = 0;
    draftTokensGenerated_ = 0;
    tokensAccepted_ = 0;
    tokensRejected_ = 0;
    totalLatencyMs_ = 0.0;
}

} // namespace Inference
} // namespace RawrXD
