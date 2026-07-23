#pragma once
#include <cstdint>
#include <cstddef>
#include <memory>
#include <functional>
#include <vector>
#include <string>

// Forward declarations for rxd::reverse types
namespace rxd::reverse {
    class ReverseEngine;
    struct ReverseModel;
    struct Match;
}

namespace Deep2 {

    // Forward declaration
    class Deep2Engine;

    // Reverse analysis results integrated with Deep2 context
    struct ReverseAnalysisResult {
        uint64_t token_id;
        uint8_t byte_value;
        double confidence;
        std::string pattern_id;
        std::string pattern_name;
        size_t offset_in_buffer;
        
        // Deep2 context
        int layer_idx;
        float attention_weight;
        bool was_speculative;
        
        // Timing
        uint64_t analysis_time_ns;
    };

    // Callback for reverse-assembly events
    using ReverseMatchCallback = std::function<void(const ReverseAnalysisResult&)>;

    class ReverseIntegration {
    public:
        ReverseIntegration();
        ~ReverseIntegration();

        // Initialize with model path
        bool initialize(const std::string& reverse_model_path);
        
        // Connect to Deep2 engine
        void attachToEngine(Deep2Engine* engine);
        void detachFromEngine();

        // Enable/disable features
        void enableRealTimeAnalysis(bool enable);
        void enableSpeculativeReverse(bool enable);
        void setCallback(ReverseMatchCallback callback);

        // Analysis methods
        std::vector<ReverseAnalysisResult> analyzeBuffer(const uint8_t* data, size_t length, int layer = -1);
        
        // Called from Deep2 engine's forward pass
        void onTokenGenerated(uint64_t token_id, const uint8_t* token_data, size_t token_len);
        void onLayerProcessed(int layer_idx, const float* activations, size_t act_len);
        void onAttentionComputed(int layer_idx, const float* attention_weights, size_t weight_len);

        // Get statistics
        struct Stats {
            size_t total_matches = 0;
            size_t speculative_hits = 0;
            size_t speculative_misses = 0;
            double average_confidence = 0.0;
            uint64_t total_analysis_time_ns = 0;
        };
        Stats getStats() const;

    private:
        struct Impl;
        std::unique_ptr<Impl> pImpl_;
    };

} // namespace Deep2
