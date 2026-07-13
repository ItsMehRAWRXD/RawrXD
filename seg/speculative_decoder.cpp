// ============================================================================
// C8: Speculative Decoding Implementation
// ============================================================================
// Draft model generates K tokens, target model verifies in parallel
// ============================================================================

#include "speculative_decoder.hpp"
#include <algorithm>
#include <random>
#include <chrono>

namespace seg {

// ============================================================================
// SpeculativeDecoder Implementation
// ============================================================================

SpeculativeDecoder::SpeculativeDecoder() = default;
SpeculativeDecoder::~SpeculativeDecoder() = default;

bool SpeculativeDecoder::Initialize(
    std::unique_ptr<DraftModel> draft,
    std::unique_ptr<TargetModel> target,
    const SpeculativeConfig& config
) {
    if (!draft || !target) {
        return false;
    }
    
    draft_model_ = std::move(draft);
    target_model_ = std::move(target);
    config_ = config;
    
    return true;
}

std::vector<uint32_t> SpeculativeDecoder::Generate(
    const std::vector<uint32_t>& prompt,
    uint32_t max_tokens,
    std::function<void(uint32_t)> token_callback
) {
    std::vector<uint32_t> generated = prompt;
    uint32_t tokens_generated = 0;
    
    while (tokens_generated < max_tokens) {
        // Speculative step
        auto step_tokens = SpeculativeStep(generated);
        
        if (step_tokens.empty()) {
            break; // No more tokens
        }
        
        // Add accepted tokens
        for (uint32_t token : step_tokens) {
            generated.push_back(token);
            tokens_generated++;
            
            if (token_callback) {
                token_callback(token);
            }
            
            if (tokens_generated >= max_tokens) {
                break;
            }
        }
    }
    
    // Return only newly generated tokens
    return std::vector<uint32_t>(generated.begin() + prompt.size(), generated.end());
}

std::vector<uint32_t> SpeculativeDecoder::SpeculativeStep(
    const std::vector<uint32_t>& context
) {
    // Telemetry: Draft generation
    auto draft_start = std::chrono::high_resolution_clock::now();
    
    // 1. Generate draft tokens
    std::vector<uint32_t> draft_tokens = draft_model_->GenerateDraft(
        context,
        config_.draft_tokens,
        config_.draft_temperature
    );
    
    auto draft_end = std::chrono::high_resolution_clock::now();
    auto draft_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        draft_end - draft_start
    );
    
    stats_.draft_time_us += draft_duration.count();
    stats_.draft_tokens_generated += draft_tokens.size();
    
    // Telemetry: Target verification
    auto target_start = std::chrono::high_resolution_clock::now();
    
    // 2. Target model verifies draft tokens in parallel
    std::vector<std::vector<float>> target_logits = target_model_->VerifyDraft(
        context,
        draft_tokens
    );
    
    auto target_end = std::chrono::high_resolution_clock::now();
    auto target_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        target_end - target_start
    );
    
    stats_.target_time_us += target_duration.count();
    
    // 3. Accept/reject logic
    AcceptanceResult result = AcceptReject(draft_tokens, target_logits);
    
    // Update statistics
    stats_.total_steps++;
    stats_.tokens_accepted += result.accepted_count;
    stats_.tokens_rejected += (result.accepted_count < draft_tokens.size()) ? 1 : 0;
    
    // Calculate acceptance rate
    if (stats_.total_steps > 0) {
        stats_.avg_acceptance_rate = static_cast<float>(stats_.tokens_accepted) /
            (stats_.tokens_accepted + stats_.tokens_rejected);
    }
    
    // Calculate speedup
    float baseline_time = target_model_->GetLatencyEstimate() * draft_tokens.size();
    float speculative_time = draft_model_->GetLatencyEstimate() * draft_tokens.size() +
                              target_model_->GetLatencyEstimate();
    stats_.speedup_vs_baseline = baseline_time / speculative_time;
    
    // 4. Build result tokens
    std::vector<uint32_t> accepted_tokens;
    
    // Add accepted draft tokens
    for (uint32_t i = 0; i < result.accepted_count && i < draft_tokens.size(); i++) {
        accepted_tokens.push_back(draft_tokens[i]);
    }
    
    // If we rejected a token, use target's token at that position
    if (result.use_target_token && result.accepted_count < draft_tokens.size()) {
        accepted_tokens.push_back(result.target_token);
    }
    
    return accepted_tokens;
}

AcceptanceResult SpeculativeDecoder::AcceptReject(
    const std::vector<uint32_t>& draft_tokens,
    const std::vector<std::vector<float>>& target_logits
) {
    AcceptanceResult result;
    result.accepted_count = 0;
    result.rejected_index = 0;
    result.use_target_token = false;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> uniform(0.0f, 1.0f);
    
    for (size_t i = 0; i < draft_tokens.size() && i < target_logits.size(); i++) {
        // Get probabilities from logits
        const auto& logits = target_logits[i];
        
        // Softmax
        float max_logit = *std::max_element(logits.begin(), logits.end());
        float sum_exp = 0.0f;
        for (float logit : logits) {
            sum_exp += std::exp(logit - max_logit);
        }
        
        // Get probability of draft token
        float draft_token_prob = std::exp(logits[draft_tokens[i]] - max_logit) / sum_exp;
        
        // Acceptance probability (simplified - should compare draft vs target dist)
        float accept_prob = std::min(1.0f, draft_token_prob / config_.min_accept_prob);
        
        // Sample acceptance
        if (uniform(gen) < accept_prob) {
            result.accepted_count++;
        } else {
            // Rejected - find alternative token from target distribution
            result.rejected_index = static_cast<uint32_t>(i);
            result.use_target_token = true;
            
            // Sample from target distribution
            float sample = uniform(gen);
            float cumsum = 0.0f;
            for (size_t j = 0; j < logits.size(); j++) {
                cumsum += std::exp(logits[j] - max_logit) / sum_exp;
                if (cumsum >= sample) {
                    result.target_token = static_cast<uint32_t>(j);
                    break;
                }
            }
            break;
        }
    }
    
    result.acceptance_rate = static_cast<float>(result.accepted_count) / draft_tokens.size();
    return result;
}

uint32_t SpeculativeDecoder::SampleToken(const std::vector<float>& logits, float temperature) {
    // Apply temperature
    std::vector<float> scaled_logits = logits;
    for (auto& logit : scaled_logits) {
        logit /= temperature;
    }
    
    // Softmax
    float max_logit = *std::max_element(scaled_logits.begin(), scaled_logits.end());
    float sum_exp = 0.0f;
    for (float logit : scaled_logits) {
        sum_exp += std::exp(logit - max_logit);
    }
    
    // Sample
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> uniform(0.0f, 1.0f);
    
    float sample = uniform(gen);
    float cumsum = 0.0f;
    for (size_t i = 0; i < scaled_logits.size(); i++) {
        cumsum += std::exp(scaled_logits[i] - max_logit) / sum_exp;
        if (cumsum >= sample) {
            return static_cast<uint32_t>(i);
        }
    }
    
    return 0; // Fallback
}

SpeculativeDecoder::Stats SpeculativeDecoder::GetStats() const {
    return stats_;
}

void SpeculativeDecoder::ResetStats() {
    stats_ = Stats{};
}

// ============================================================================
// NGramDraftModel Implementation
// ============================================================================

NGramDraftModel::NGramDraftModel(uint32_t vocab_size) : vocab_size_(vocab_size) {}

void NGramDraftModel::BuildStats(const std::vector<std::vector<uint32_t>>& sequences) {
    // Count bigram occurrences
    std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t>> counts;
    
    for (const auto& seq : sequences) {
        for (size_t i = 0; i + 1 < seq.size(); i++) {
            counts[seq[i]][seq[i + 1]]++;
        }
    }
    
    // Convert to probabilities
    for (const auto& [first, second_counts] : counts) {
        uint32_t total = 0;
        for (const auto& [second, count] : second_counts) {
            total += count;
        }
        
        for (const auto& [second, count] : second_counts) {
            bigrams_[first].push_back({second, static_cast<float>(count) / total});
        }
    }
}

std::vector<uint32_t> NGramDraftModel::GenerateDraft(
    const std::vector<uint32_t>& context,
    uint32_t num_tokens,
    float temperature
) {
    std::vector<uint32_t> draft;
    
    if (context.empty()) {
        return draft;
    }
    
    uint32_t current = context.back();
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> uniform(0.0f, 1.0f);
    
    for (uint32_t i = 0; i < num_tokens; i++) {
        auto it = bigrams_.find(current);
        if (it == bigrams_.end() || it->second.empty()) {
            // No bigram stats - sample uniformly
            std::uniform_int_distribution<uint32_t> token_dist(0, vocab_size_ - 1);
            current = token_dist(gen);
        } else {
            // Sample from bigram distribution
            float sample = uniform(gen);
            float cumsum = 0.0f;
            
            for (const auto& [token, prob] : it->second) {
                cumsum += prob;
                if (cumsum >= sample) {
                    current = token;
                    break;
                }
            }
        }
        
        draft.push_back(current);
    }
    
    return draft;
}

// ============================================================================
// SEGTargetModel Implementation
// ============================================================================

SEGTargetModel::SEGTargetModel(
    Executor& executor,
    Graph& graph,
    Memory& memory
) : executor_(executor), graph_(graph), memory_(memory) {}

std::vector<std::vector<float>> SEGTargetModel::VerifyDraft(
    const std::vector<uint32_t>& context,
    const std::vector<uint32_t>& draft_tokens
) {
    std::vector<std::vector<float>> all_logits;
    
    // Build extended context with each draft token position
    std::vector<uint32_t> extended_context = context;
    
    for (size_t i = 0; i < draft_tokens.size(); i++) {
        // Execute one forward pass
        // In real implementation, this would use SEG executor
        // For now, return dummy logits
        
        std::vector<float> logits(32000, -10.0f); // Vocab size
        logits[draft_tokens[i]] = 5.0f; // High probability for draft token
        
        // Add some noise for realistic acceptance/rejection
        std::random_device rd;
        std::mt19937 gen(rd());
        std::normal_distribution<float> noise(0.0f, 1.0f);
        
        for (auto& logit : logits) {
            logit += noise(gen);
        }
        
        all_logits.push_back(logits);
        extended_context.push_back(draft_tokens[i]);
    }
    
    return all_logits;
}

} // namespace seg
