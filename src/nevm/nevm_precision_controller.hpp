//============================================================================
// nevm_precision_controller.hpp
// RawrXD N-EVM Precision Controller
// Telemetry-driven representation selection
//============================================================================

#pragma once

#include "nevm_isa.hpp"
#include "nevm_mmu.hpp"
#include <deque>
#include <cmath>

namespace RawrXD {
namespace NEVM {

using ISA::PrecisionMode;
using ISA::BlockState;
using ISA::VirtualTensorAddress;

//============================================================================
// Telemetry Sample
// Captures runtime behavior for decision making
//============================================================================

struct TelemetrySample {
    uint64_t timestamp;
    VirtualTensorAddress vta;
    
    // Decode metrics
    float decode_latency_ms;
    size_t bytes_decoded;
    
    // Quality metrics
    float reconstruction_error;
    float token_acceptance_rate;
    
    // Memory pressure
    size_t ram_available;
    size_t vram_available;
    float memory_pressure;  // 0.0-1.0
    
    // Compute metrics
    float compute_latency_ms;
    uint32_t flops_executed;
};

//============================================================================
// Precision Controller
// Decides optimal representation based on telemetry
//============================================================================

class PrecisionController {
public:
    struct Config {
        // Latency budget (ms)
        float target_decode_latency;
        float target_compute_latency;
        
        // Quality thresholds
        float max_reconstruction_error;
        float min_acceptance_rate;
        
        // Memory pressure thresholds
        float critical_memory_pressure;   // Evict aggressively
        float high_memory_pressure;       // Prefer compressed
        float low_memory_pressure;        // Allow expansion
        
        // Adaptive weights
        float latency_weight;
        float quality_weight;
        float memory_weight;
    };
    
    static Config DefaultConfig();
    
    explicit PrecisionController(const Config& config);
    ~PrecisionController();
    
    // Record telemetry
    void RecordDecode(const TelemetrySample& sample);
    void RecordCompute(const TelemetrySample& sample);
    void RecordAcceptance(float acceptance_rate);
    
    // Decide optimal representation
    PrecisionMode SelectRepresentation(
        VirtualTensorAddress vta,
        const BlockState& current_state,
        float predicted_importance
    );
    
    // Batch decision for multiple blocks
    std::vector<std::pair<VirtualTensorAddress, PrecisionMode>> 
    OptimizeBatch(const std::vector<BlockState>& blocks);
    
    // Medusa/speculative feedback
    void OnSpeculativeToken(float acceptance_probability);
    void OnVerificationComplete(bool accepted, float error);
    
    // Get current system state
    struct SystemState {
        float avg_decode_latency;
        float avg_compute_latency;
        float avg_reconstruction_error;
        float memory_pressure;
        float recent_acceptance_rate;
        uint64_t samples_collected;
    };
    SystemState GetSystemState() const;
    
    // Reset statistics
    void Reset();
    
private:
    Config config_;
    
    // Rolling windows for statistics
    std::deque<TelemetrySample> decode_history_;
    std::deque<TelemetrySample> compute_history_;
    std::deque<float> acceptance_history_;
    
    static constexpr size_t MAX_HISTORY = 1000;
    
    mutable std::mutex mutex_;
    
    // Private methods
    float CalculateScore(
        PrecisionMode format,
        const BlockState& state,
        float importance
    ) const;
    
    float EstimateLatency(PrecisionMode format) const;
    float EstimateQuality(PrecisionMode format) const;
    float EstimateMemory(PrecisionMode format) const;
    
    void TrimHistory();
    float GetAverageAcceptance() const;
};

//============================================================================
// Multi-State Tensor Block
// Maintains multiple representations of same data
//============================================================================

class MultiStateBlock {
public:
    struct State {
        PrecisionMode format;
        std::vector<uint8_t> data;
        float reconstruction_error;
        float decode_latency_ms;
        size_t memory_size;
        uint64_t last_used;
    };
    
    explicit MultiStateBlock(VirtualTensorAddress vta);
    ~MultiStateBlock();
    
    // Add a representation
    bool AddState(PrecisionMode format, std::vector<uint8_t>&& data,
                   float error, float latency);
    
    // Get best state for requirements
    const State* SelectState(float max_error, float max_latency, 
                              size_t max_memory) const;
    
    // Get specific format if available
    const State* GetState(PrecisionMode format) const;
    
    // Evict least-used states
    size_t EvictOldStates(uint64_t min_age);
    
    // Statistics
    size_t GetTotalMemory() const;
    int GetStateCount() const;
    
private:
    VirtualTensorAddress vta_;
    std::unordered_map<PrecisionMode, State> states_;
    mutable std::shared_mutex mutex_;
};

//============================================================================
// Adaptive Precision Manager
// High-level coordinator
//============================================================================

class AdaptivePrecisionManager {
public:
    AdaptivePrecisionManager(
        NeuralMMU* mmu,
        PrecisionController* controller
    );
    ~AdaptivePrecisionManager();
    
    // Initialize block with multiple states
    bool InitializeBlock(VirtualTensorAddress vta, 
                         const void* source_data,
                         size_t source_size,
                         PrecisionMode source_format);
    
    // Access block with automatic precision selection
    void* AccessBlock(VirtualTensorAddress vta, float predicted_importance);
    
    // Force specific precision
    void* AccessBlockWithPrecision(VirtualTensorAddress vta, 
                                     PrecisionMode required_format);
    
    // Background optimization
    void OptimizeMemory();
    void GenerateMissingRepresentations();
    
    // Medusa integration
    void OnMedusaPrediction(const std::vector<float>& acceptance_probs);
    void OnTokenAccepted(int token_id);
    void OnTokenRejected(int token_id);
    
private:
    NeuralMMU* mmu_;
    PrecisionController* controller_;
    
    std::unordered_map<uint64_t, std::unique_ptr<MultiStateBlock>> blocks_;
    std::mutex blocks_mutex_;
    
    // Current speculative state
    bool speculative_mode_;
    std::vector<VirtualTensorAddress> active_blocks_;
};

} // namespace NEVM
} // namespace RawrXD
