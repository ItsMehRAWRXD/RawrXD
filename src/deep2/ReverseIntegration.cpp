// ============================================================================
// ReverseIntegration.cpp - Bridge between BigDaddyG Reverse Engine and Deep2
// ============================================================================

#include "ReverseIntegration.hpp"
#include "../reverse/ReverseEngine.hpp"
#include "../reverse/ReverseModelLoader.hpp"
#include <chrono>
#include <unordered_map>
#include <mutex>
#include <algorithm>
#include <iostream>
#include <iomanip>

namespace Deep2 {

    struct ReverseIntegration::Impl {
        std::unique_ptr<rxd::reverse::ReverseEngine> reverse_engine;
        std::unique_ptr<rxd::reverse::ReverseModel> reverse_model;
        Deep2Engine* deep2_engine = nullptr;
        
        bool real_time_enabled = true;
        bool speculative_reverse_enabled = false;
        ReverseMatchCallback callback;
        
        // Statistics
        Stats stats{};
        std::mutex stats_mutex;
        
        // Cache for recent tokens
        struct TokenCache {
            uint64_t token_id;
            uint8_t byte_value;
            double confidence;
            std::chrono::steady_clock::time_point timestamp;
        };
        std::unordered_map<uint64_t, TokenCache> token_cache;
        static constexpr size_t MAX_CACHE_SIZE = 1024;
        
        // Layer-specific results
        std::unordered_map<int, std::vector<ReverseAnalysisResult>> layer_results;
        
        Impl() = default;
        
        void addToCache(uint64_t token_id, uint8_t byte_value, double confidence) {
            std::lock_guard<std::mutex> lock(stats_mutex);
            token_cache[token_id] = {token_id, byte_value, confidence, 
                                     std::chrono::steady_clock::now()};
            
            // Trim cache if too large
            if (token_cache.size() > MAX_CACHE_SIZE) {
                auto oldest = std::min_element(
                    token_cache.begin(), token_cache.end(),
                    [](const auto& a, const auto& b) {
                        return a.second.timestamp < b.second.timestamp;
                    }
                );
                if (oldest != token_cache.end()) {
                    token_cache.erase(oldest);
                }
            }
        }
        
        bool getFromCache(uint64_t token_id, uint8_t& byte_value, double& confidence) {
            std::lock_guard<std::mutex> lock(stats_mutex);
            auto it = token_cache.find(token_id);
            if (it != token_cache.end()) {
                byte_value = it->second.byte_value;
                confidence = it->second.confidence;
                return true;
            }
            return false;
        }
    };

    // === Constructor / Destructor ===
    
    ReverseIntegration::ReverseIntegration() 
        : pImpl_(std::make_unique<Impl>()) {}

    ReverseIntegration::~ReverseIntegration() {
        detachFromEngine();
    }

    // === Initialization ===

    bool ReverseIntegration::initialize(const std::string& reverse_model_path) {
        try {
            pImpl_->reverse_model = std::make_unique<rxd::reverse::ReverseModel>(
                rxd::reverse::ReverseModelLoader::LoadFromFile(reverse_model_path)
            );
            pImpl_->reverse_engine = std::make_unique<rxd::reverse::ReverseEngine>(*pImpl_->reverse_model);
            
            // Log model info
            std::cout << "[ReverseIntegration] Loaded model: " << pImpl_->reverse_model->name 
                      << " v" << pImpl_->reverse_model->version << std::endl;
            std::cout << "[ReverseIntegration] Patterns: " << pImpl_->reverse_model->patterns.size() 
                      << ", Samples: " << pImpl_->reverse_model->samples.size() << std::endl;
            
            return true;
        } catch (const std::exception& e) {
            std::cerr << "[ReverseIntegration] ERROR: Failed to load reverse model: " 
                      << e.what() << std::endl;
            return false;
        }
    }

    // === Engine Attachment ===

    void ReverseIntegration::attachToEngine(Deep2Engine* engine) {
        if (pImpl_->deep2_engine == engine) return;
        
        detachFromEngine();
        pImpl_->deep2_engine = engine;
        
        if (engine) {
            std::cout << "[ReverseIntegration] Attached to Deep2Engine at " << engine << std::endl;
        }
    }

    void ReverseIntegration::detachFromEngine() {
        if (pImpl_->deep2_engine) {
            std::cout << "[ReverseIntegration] Detached from Deep2Engine" << std::endl;
            pImpl_->deep2_engine = nullptr;
        }
    }

    // === Configuration ===

    void ReverseIntegration::enableRealTimeAnalysis(bool enable) {
        pImpl_->real_time_enabled = enable;
        std::cout << "[ReverseIntegration] Real-time analysis " 
                  << (enable ? "enabled" : "disabled") << std::endl;
    }

    void ReverseIntegration::enableSpeculativeReverse(bool enable) {
        pImpl_->speculative_reverse_enabled = enable;
        std::cout << "[ReverseIntegration] Speculative reverse " 
                  << (enable ? "enabled" : "disabled") << std::endl;
    }

    void ReverseIntegration::setCallback(ReverseMatchCallback callback) {
        pImpl_->callback = std::move(callback);
    }

    // === Core Analysis ===

    std::vector<ReverseAnalysisResult> ReverseIntegration::analyzeBuffer(
        const uint8_t* data, size_t length, int layer) {
        
        std::vector<ReverseAnalysisResult> results;
        
        if (!pImpl_->real_time_enabled || data == nullptr || length == 0) {
            return results;
        }

        if (!pImpl_->reverse_engine) {
            return results;
        }

        auto start_time = std::chrono::high_resolution_clock::now();

        // Scan using reverse engine
        auto matches = pImpl_->reverse_engine->Scan(data, length);

        // Convert to Deep2 integration format
        for (const auto& match : matches) {
            ReverseAnalysisResult result;
            result.byte_value = match.predictedByte;
            result.confidence = match.confidence;
            result.pattern_id = match.patternId;
            result.pattern_name = match.patternName;
            result.offset_in_buffer = match.offset;
            result.layer_idx = layer;
            result.attention_weight = 0.0f;
            result.was_speculative = false;
            result.token_id = static_cast<uint64_t>(match.offset);
            
            results.push_back(result);

            // Cache the result
            pImpl_->addToCache(result.token_id, result.byte_value, result.confidence);
            
            // Trigger callback if set
            if (pImpl_->callback) {
                pImpl_->callback(result);
            }
        }

        // Update statistics
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
        
        {
            std::lock_guard<std::mutex> lock(pImpl_->stats_mutex);
            pImpl_->stats.total_matches += results.size();
            pImpl_->stats.total_analysis_time_ns += duration.count();
            
            double total_conf = 0.0;
            for (const auto& r : results) {
                total_conf += r.confidence;
            }
            if (!results.empty()) {
                pImpl_->stats.average_confidence = 
                    (pImpl_->stats.average_confidence + (total_conf / results.size())) / 2.0;
            }
        }

        return results;
    }

    // === Deep2 Callbacks ===

    void ReverseIntegration::onTokenGenerated(uint64_t token_id, const uint8_t* token_data, size_t token_len) {
        if (!pImpl_->real_time_enabled || token_len == 0) return;
        
        // Analyze the token data
        auto results = analyzeBuffer(token_data, token_len, -1);
        
        if (!results.empty() && pImpl_->speculative_reverse_enabled) {
            // Use results for speculative decoding hints
            for (const auto& result : results) {
                if (result.confidence > 0.8) {
                    // High confidence - can influence Deep2's generation
                    if (pImpl_->deep2_engine) {
                        std::cout << "[ReverseIntegration] Speculative suggestion: 0x" 
                                  << std::hex << static_cast<int>(result.byte_value) 
                                  << " (conf: " << std::fixed << std::setprecision(3) 
                                  << result.confidence << ")" << std::endl;
                    }
                }
            }
        }
    }

    void ReverseIntegration::onLayerProcessed(int layer_idx, const float* activations, size_t act_len) {
        if (!pImpl_->real_time_enabled || activations == nullptr || act_len == 0) {
            return;
        }
        
        // Convert activations to bytes for analysis
        std::vector<uint8_t> byte_data(std::min(act_len, size_t(256)));
        for (size_t i = 0; i < byte_data.size(); ++i) {
            byte_data[i] = static_cast<uint8_t>(
                std::max(0.0f, std::min(255.0f, activations[i] * 255.0f))
            );
        }
        
        auto results = analyzeBuffer(byte_data.data(), byte_data.size(), layer_idx);
        
        // Store layer-specific results
        pImpl_->layer_results[layer_idx] = std::move(results);
    }

    void ReverseIntegration::onAttentionComputed(int layer_idx, const float* attention_weights, size_t weight_len) {
        // Match reverse patterns with attention weights
        auto it = pImpl_->layer_results.find(layer_idx);
        if (it != pImpl_->layer_results.end()) {
            for (auto& result : it->second) {
                if (result.offset_in_buffer < weight_len) {
                    result.attention_weight = attention_weights[result.offset_in_buffer];
                }
            }
        }
    }

    // === Statistics ===

    ReverseIntegration::Stats ReverseIntegration::getStats() const {
        std::lock_guard<std::mutex> lock(pImpl_->stats_mutex);
        return pImpl_->stats;
    }

} // namespace Deep2
