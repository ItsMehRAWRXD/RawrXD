#include "speculative_decoder.h"
#include <algorithm>
#include <cmath>

namespace RawrXD {

SpeculativeDecoder::SpeculativeDecoder()
    : m_enabled(true), m_speculation_depth(4), m_confidence_threshold(0.6f)
{
    m_last_prediction_start = std::chrono::high_resolution_clock::now();
}

std::vector<uint32_t> SpeculativeDecoder::SpeculateCandidates(
    const std::vector<uint32_t>& context,
    size_t top_k)
{
    if (!m_enabled || context.empty()) {
        return {};
    }

    auto start_time = std::chrono::high_resolution_clock::now();

    std::vector<uint32_t> candidates;
    
    // Look at last token to predict next ones
    if (!context.empty()) {
        uint32_t last_token = context.back();
        
        // Try trigram first (more context)
        if (context.size() >= 2) {
            uint32_t trigram_key = (context[context.size() - 2] << 16) | last_token;
            auto trigram_it = m_trigram_model.find(trigram_key);
            if (trigram_it != m_trigram_model.end()) {
                // Sort by frequency
                auto sorted = trigram_it->second;
                std::sort(sorted.begin(), sorted.end(),
                    [](const auto& a, const auto& b) { return a.second > b.second; });
                
                for (size_t i = 0; i < std::min(top_k, sorted.size()); i++) {
                    if (sorted[i].second > 0) {
                        candidates.push_back(sorted[i].first);
                    }
                }
                if (candidates.size() >= top_k) goto done;
            }
        }
        
        // Fall back to bigram if needed
        {
            auto bigram_it = m_bigram_model.find(last_token);
            if (bigram_it != m_bigram_model.end()) {
                auto sorted = bigram_it->second;
                std::sort(sorted.begin(), sorted.end(),
                    [](const auto& a, const auto& b) { return a.second > b.second; });
                
                for (size_t i = 0; i < std::min(top_k, sorted.size()); i++) {
                    if (sorted[i].second > 0 && 
                        std::find(candidates.begin(), candidates.end(), sorted[i].first) == candidates.end()) {
                        candidates.push_back(sorted[i].first);
                    }
                }
            }
        }
    }
    
done:
    // Record timing
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_stats.avg_speculation_time_ms = 
            (m_stats.avg_speculation_time_ms * m_stats.total_predictions + duration_ms) /
            (m_stats.total_predictions + 1);
        m_stats.total_predictions++;
    }
    
    return candidates;
}

bool SpeculativeDecoder::ValidatePrediction(uint32_t predicted_token, uint32_t actual_token)
{
    bool correct = (predicted_token == actual_token);
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (correct) {
            m_stats.correct_predictions++;
        } else {
            m_stats.incorrect_predictions++;
        }
        
        if (m_stats.correct_predictions + m_stats.incorrect_predictions > 0) {
            m_stats.accuracy_rate = 
                static_cast<double>(m_stats.correct_predictions) /
                (m_stats.correct_predictions + m_stats.incorrect_predictions);
        }
    }
    
    return correct;
}

std::vector<std::vector<float>> SpeculativeDecoder::SpeculativePrecompute(
    const std::vector<uint32_t>& candidate_tokens,
    const std::vector<uint32_t>& context)
{
    if (!m_enabled) {
        return {};
    }

    std::vector<std::vector<float>> results;
    
    // Placeholder for actual forward pass precomputation
    // In production, this would:
    // 1. Run partial transformer layers in parallel
    // 2. Compute logits for candidate tokens
    // 3. Return pre-computed scores for validation
    
    for (const auto& token : candidate_tokens) {
        // Dummy implementation: return a softmax distribution
        std::vector<float> logits(1000, -1e6f);  // Vocabulary size ~1000 for tiny models
        logits[token] = 1.0f;  // High confidence in the candidate
        results.push_back(logits);
    }
    
    return results;
}

void SpeculativeDecoder::LearnFromPrediction(
    const std::vector<uint32_t>& context,
    uint32_t predicted_token,
    uint32_t actual_token,
    bool was_correct)
{
    if (!m_enabled || context.empty()) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_mutex);

        // Update bigram model
        {
            uint32_t last_token = context.back();
            auto& bigram_entry = m_bigram_model[last_token];
            
            auto it = std::find_if(bigram_entry.begin(), bigram_entry.end(),
                [actual_token](const auto& p) { return p.first == actual_token; });
            
            if (it != bigram_entry.end()) {
                it->second += (was_correct ? 2 : 1);  // Boost correct predictions
            } else {
                bigram_entry.emplace_back(actual_token, 1);
            }
        }

        // Update trigram model if we have enough context
        if (context.size() >= 2) {
            uint32_t trigram_key = (context[context.size() - 2] << 16) | context.back();
            auto& trigram_entry = m_trigram_model[trigram_key];
            
            auto it = std::find_if(trigram_entry.begin(), trigram_entry.end(),
                [actual_token](const auto& p) { return p.first == actual_token; });
            
            if (it != trigram_entry.end()) {
                it->second += (was_correct ? 2 : 1);
            } else {
                trigram_entry.emplace_back(actual_token, 1);
            }
        }
    }
}

} // namespace RawrXD

