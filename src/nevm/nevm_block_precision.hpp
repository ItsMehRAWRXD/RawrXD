//============================================================================
// nevm_block_precision.hpp
// RawrXD N-EVM Block-Granular Precision Controller
// Different precisions for different parts of the same layer
//============================================================================

#pragma once

#include "nevm_precision_controller.hpp"
#include "nevm_residency.hpp"
#include <map>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Block Granularity Types
// Sub-layer precision control
//============================================================================

enum class BlockGranularity {
    LAYER = 0,          // Entire layer same precision
    TENSOR = 1,         // Per-tensor (Q, K, V, O, FFN)
    HEAD = 2,           // Per-attention-head
    BLOCK = 3,          // Per-weight-block (4MB chunks)
    ELEMENT = 4         // Per-element (extreme, not practical)
};

//============================================================================
// Sub-Layer Block ID
// Identifies a specific block within a layer
//============================================================================

struct SubLayerBlockID {
    uint8_t layer_id;
    uint8_t tensor_type;      // Q=0, K=1, V=2, O=3, Gate=4, Up=5, Down=6
    uint16_t head_id;         // For head-granular (0 if not applicable)
    uint32_t block_idx;       // For block-granular
    
    bool operator==(const SubLayerBlockID& other) const {
        return layer_id == other.layer_id &&
               tensor_type == other.tensor_type &&
               head_id == other.head_id &&
               block_idx == other.block_idx;
    }
    
    bool operator<(const SubLayerBlockID& other) const {
        if (layer_id != other.layer_id) return layer_id < other.layer_id;
        if (tensor_type != other.tensor_type) return tensor_type < other.tensor_type;
        if (head_id != other.head_id) return head_id < other.head_id;
        return block_idx < other.block_idx;
    }
    
    uint64_t Hash() const {
        return (static_cast<uint64_t>(layer_id) << 56) |
               (static_cast<uint64_t>(tensor_type) << 48) |
               (static_cast<uint64_t>(head_id) << 32) |
               block_idx;
    }
};

// Hash function for unordered_map
struct SubLayerBlockIDHash {
    size_t operator()(const SubLayerBlockID& id) const {
        return std::hash<uint64_t>{}(id.Hash());
    }
};

//============================================================================
// Block Precision Profile
// Precision assignment for a specific block
//============================================================================

struct BlockPrecisionProfile {
    SubLayerBlockID block_id;
    PrecisionMode precision;
    float importance_score;      // 0.0-1.0
    float measured_error;        // Historical reconstruction error
    uint64_t access_count;
    uint64_t last_access_tick;
    
    // Constraints
    float min_acceptable_quality;
    float max_acceptable_latency_ms;
};

//============================================================================
// Layer Precision Map
// Complete precision assignment for a layer
//============================================================================

class LayerPrecisionMap {
public:
    explicit LayerPrecisionMap(uint8_t layer_id, BlockGranularity granularity);
    
    // Set precision for specific block
    void SetBlockPrecision(const SubLayerBlockID& block_id, PrecisionMode precision);
    
    // Get precision for specific block
    PrecisionMode GetBlockPrecision(const SubLayerBlockID& block_id) const;
    
    // Get all blocks at specific precision
    std::vector<SubLayerBlockID> GetBlocksAtPrecision(PrecisionMode precision) const;
    
    // Get precision distribution
    std::map<PrecisionMode, uint32_t> GetPrecisionDistribution() const;
    
    // Calculate effective bits per parameter
    float CalculateEffectiveBits() const;
    
    // Memory footprint
    size_t CalculateMemoryFootprint(size_t elements_per_block) const;
    
private:
    uint8_t layer_id_;
    BlockGranularity granularity_;
    std::unordered_map<SubLayerBlockID, BlockPrecisionProfile, SubLayerBlockIDHash> profiles_;
    mutable std::shared_mutex mutex_;
};

//============================================================================
// Block-Granular Precision Controller
// Fine-grained precision control within layers
//============================================================================

class BlockGranularPrecisionController {
public:
    struct Config {
        BlockGranularity default_granularity;
        float sensitivity_threshold;      // When to upgrade precision
        float insensitivity_threshold;  // When to downgrade precision
        uint32_t profiling_window;      // Tokens to profile before deciding
    };
    
    static Config DefaultConfig();
    
    explicit BlockGranularPrecisionController(const Config& config);
    
    // Initialize layer map
    void InitializeLayer(uint8_t layer_id, 
                         uint32_t num_heads,
                         uint32_t num_blocks_per_tensor);
    
    // Record per-block telemetry
    void RecordBlockTelemetry(const SubLayerBlockID& block_id,
                               float reconstruction_error,
                               float compute_time_ms,
                               float output_magnitude);
    
    // Get precision for specific block
    PrecisionMode GetBlockPrecision(const SubLayerBlockID& block_id);
    
    // Optimize entire layer based on telemetry
    void OptimizeLayer(uint8_t layer_id);
    
    // Get layer map (for inspection)
    const LayerPrecisionMap* GetLayerMap(uint8_t layer_id) const;
    
    // Force precision for specific block (manual override)
    void ForceBlockPrecision(const SubLayerBlockID& block_id, PrecisionMode precision);
    
    // Statistics
    struct Stats {
        uint64_t blocks_profiled;
        uint64_t precision_changes;
        uint64_t upgrades;
        uint64_t downgrades;
        float avg_effective_bits;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    
    std::unordered_map<uint8_t, std::unique_ptr<LayerPrecisionMap>> layer_maps_;
    mutable std::shared_mutex maps_mutex_;
    
    // Telemetry history per block
    struct BlockTelemetry {
        std::deque<float> errors;
        std::deque<float> compute_times;
        std::deque<float> magnitudes;
    };
    std::unordered_map<SubLayerBlockID, BlockTelemetry, SubLayerBlockIDHash> telemetry_;
    mutable std::mutex telemetry_mutex_;
    
    Stats stats_;
    mutable std::mutex stats_mutex_;
    
    // Private methods
    float CalculateBlockSensitivity(const SubLayerBlockID& block_id);
    PrecisionMode SelectOptimalPrecision(const SubLayerBlockID& block_id, 
                                        float sensitivity);
    void UpdateLayerMap(uint8_t layer_id);
};

//============================================================================
// Attention Head Profiler
// Profile individual attention heads for precision needs
//============================================================================

class AttentionHeadProfiler {
public:
    struct HeadMetrics {
        uint8_t layer_id;
        uint16_t head_id;
        
        // Attention pattern metrics
        float avg_attention_entropy;
        float max_attention_score;
        float sparsity;              // % of near-zero attention weights
        
        // Output contribution
        float output_norm;
        float gradient_magnitude;      // If available
        
        // Precision sensitivity
        float fp16_vs_q4_error;
        float fp16_vs_q2_error;
    };
    
    void RecordHeadOutput(uint8_t layer_id, uint16_t head_id,
                          const float* attention_weights,
                          uint32_t seq_len,
                          const float* output,
                          uint32_t head_dim);
    
    HeadMetrics GetHeadMetrics(uint8_t layer_id, uint16_t head_id) const;
    
    // Get heads sorted by sensitivity (most sensitive first)
    std::vector<HeadMetrics> GetSensitiveHeads(uint8_t layer_id, 
                                                  float threshold = 0.8f) const;
    
    // Recommend precision per head
    std::map<uint16_t, PrecisionMode> RecommendHeadPrecisions(uint8_t layer_id);
    
private:
    std::map<std::pair<uint8_t, uint16_t>, HeadMetrics> metrics_;
    mutable std::mutex metrics_mutex_;
};

//============================================================================
// FFN Block Profiler
// Profile FFN blocks for precision needs
//============================================================================

class FFNBlockProfiler {
public:
    struct BlockMetrics {
        uint8_t layer_id;
        uint32_t block_id;
        
        // Activation metrics
        float activation_sparsity;
        float activation_magnitude;
        
        // Weight importance
        float weight_magnitude;
        float weight_variance;
        
        // Output contribution
        float output_contribution;
    };
    
    void RecordFFNOutput(uint8_t layer_id, uint32_t block_id,
                         const float* activations,
                         uint32_t activation_count,
                         const float* output,
                         uint32_t output_dim);
    
    // Recommend which FFN blocks can use lower precision
    std::vector<uint32_t> GetCompressibleBlocks(uint8_t layer_id, 
                                                float sparsity_threshold = 0.9f) const;
    
private:
    std::map<std::pair<uint8_t, uint32_t>, BlockMetrics> metrics_;
    mutable std::mutex metrics_mutex_;
};

} // namespace NEVM
} // namespace RawrXD
