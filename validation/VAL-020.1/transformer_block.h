// transformer_block.h
// VAL-020.1 Transformer Block Orchestrator
// Composes VAL-019 primitives into validated transformer block

#ifndef TRANSFORMER_BLOCK_H
#define TRANSFORMER_BLOCK_H

#include <string>
#include <vector>
#include <memory>
#include "tensor_manifest.h"
#include "topology_recorder.h"

namespace val020 {

// Block configuration
struct TransformerBlockConfig {
    size_t hidden_dim = 4096;
    size_t num_heads = 32;
    size_t head_dim = 128;
    size_t ffn_dim = 11008;
    size_t vocab_size = 32000;
    float epsilon = 1e-6f;
    float rope_theta = 10000.0f;
    
    std::string to_json() const;
};

// Intermediate tensor storage
struct IntermediateTensors {
    // S1: Embedding
    std::vector<float> S1_embedding_out;
    TensorManifest S1_manifest;
    
    // S2: RMSNorm #1
    std::vector<float> S2_rmsnorm_out;
    TensorManifest S2_manifest;
    
    // S3: QKV Projection
    std::vector<float> S3_qkv_out;
    TensorManifest S3_manifest;
    
    // S4: RoPE
    std::vector<float> S4_rope_out;
    TensorManifest S4_manifest;
    
    // S5: Attention
    std::vector<float> S5_attention_out;
    TensorManifest S5_manifest;
    
    // S6: KV Cache (state, not output tensor)
    struct KVCacheState {
        std::vector<float> keys;
        std::vector<float> values;
        size_t seq_len = 0;
        TensorManifest manifest;
    };
    KVCacheState S6_kv_cache;
    
    // S7: FFN
    std::vector<float> S7_ffn_out;
    TensorManifest S7_manifest;
    
    // S8: Residual
    std::vector<float> S8_residual_out;
    TensorManifest S8_manifest;
    
    // S9: RMSNorm #2
    std::vector<float> S9_rmsnorm_out;
    TensorManifest S9_manifest;
    
    // Capture all manifests
    std::vector<TensorManifest> get_all_manifests() const;
};

// Block execution result
struct BlockExecutionResult {
    bool success;
    std::string error_message;
    
    IntermediateTensors intermediates;
    std::vector<float> final_output;
    TensorManifest output_manifest;
    
    ExecutionTopology topology;
    
    // Validation metrics
    struct ValidationMetrics {
        double max_error;
        double mean_error;
        double runtime_ms;
        bool determinism_verified;
    };
    ValidationMetrics metrics;
    
    // Serialization
    std::string to_json() const;
    void save_evidence(const std::string& path) const;
};

// Transformer block orchestrator
class TransformerBlock {
public:
    explicit TransformerBlock(const TransformerBlockConfig& config);
    
    // Execute full block
    BlockExecutionResult execute(
        const std::vector<int32_t>& input_tokens,
        const std::string& reference_output_path = ""
    );
    
    // Execute with evidence capture
    BlockExecutionResult execute_with_evidence(
        const std::vector<int32_t>& input_tokens,
        TopologyRecorder& recorder,
        ManifestRegistry& registry,
        const std::string& evidence_dir
    );
    
    // Triple-run determinism verification (G4)
    bool verify_determinism(
        const std::vector<int32_t>& input_tokens,
        int num_runs = 3
    );
    
private:
    TransformerBlockConfig config_;
    
    // Individual kernel executions
    bool execute_embedding(const std::vector<int32_t>& tokens,
                          std::vector<float>& output,
                          TensorManifest& manifest);
    
    bool execute_rmsnorm(const std::vector<float>& input,
                        std::vector<float>& output,
                        TensorManifest& manifest,
                        const std::string& tensor_id);
    
    bool execute_qkv_projection(const std::vector<float>& input,
                              std::vector<float>& output,
                              TensorManifest& manifest);
    
    bool execute_rope(std::vector<float>& qkv_tensor,  // in-place
                     size_t seq_len,
                     TensorManifest& manifest);
    
    bool execute_attention(const std::vector<float>& qkv,
                          IntermediateTensors::KVCacheState& kv_cache,
                          std::vector<float>& output,
                          TensorManifest& manifest);
    
    bool execute_ffn(const std::vector<float>& input,
                    std::vector<float>& output,
                    TensorManifest& manifest);
    
    bool execute_residual(const std::vector<float>& a,
                         const std::vector<float>& b,
                         std::vector<float>& output,
                         TensorManifest& manifest);
};

} // namespace val020

#endif // TRANSFORMER_BLOCK_H
