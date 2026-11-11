#pragma once
// ============================================================================
// ReferenceRunner — llama.cpp reference execution with activation capture
// ============================================================================
// Purpose: Run llama.cpp forward pass and capture intermediate activations
// for numerical parity comparison with native IR executor
// ============================================================================

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstdint>
#include <functional>

namespace RawrXD {
namespace CLI {

// Activation capture from llama.cpp
struct ReferenceActivation {
    std::string op_name;           // e.g., "embedding", "layer_0_attn_norm", "layer_0_attn_q"
    uint32_t op_index;             // Index in execution order (0-299)
    std::vector<float> data;       // Flattened activation tensor
    std::vector<uint64_t> shape;   // Tensor shape
    size_t element_count = 0;
    
    bool Valid() const { return !data.empty() && element_count > 0; }
};

// Reference execution result
struct ReferenceResult {
    std::vector<uint32_t> tokens;           // Generated token sequence
    std::vector<float> final_logits;        // Final logits [vocab_size]
    std::vector<ReferenceActivation> activations;  // All captured activations
    uint32_t predicted_token = 0;           // Argmax token
    double execution_time_ms = 0.0;
    bool success = false;
    std::string error_message;
    
    // Get activation by op index
    const ReferenceActivation* GetActivation(uint32_t op_index) const {
        for (const auto& act : activations) {
            if (act.op_index == op_index) return &act;
        }
        return nullptr;
    }
    
    // Get activation by name
    const ReferenceActivation* GetActivationByName(const std::string& name) const {
        for (const auto& act : activations) {
            if (act.op_name == name) return &act;
        }
        return nullptr;
    }
};

// Configuration for reference runner
struct ReferenceConfig {
    std::string model_path;
    std::string llama_cpp_path;          // Path to llama.cpp build directory
    std::vector<uint32_t> input_tokens;  // Input token sequence
    uint32_t max_tokens = 1;             // Number of tokens to generate
    uint32_t n_threads = 0;              // 0 = auto
    bool verbose = false;
    bool capture_all_activations = true; // Capture all intermediate activations
    std::vector<uint32_t> capture_op_indices; // Specific ops to capture (empty = all)
    
    // Sampling config
    float temperature = 1.0f;
    int top_k = 40;
    float top_p = 0.9f;
    uint32_t seed = 42;
};

// Reference runner using llama.cpp as ground truth
class ReferenceRunner {
public:
    ReferenceRunner() = default;
    ~ReferenceRunner() = default;
    
    // Initialize reference runner with model
    bool Initialize(const ReferenceConfig& config);
    
    // Run reference forward pass and capture activations
    ReferenceResult RunForward(const std::vector<uint32_t>& input_tokens);
    
    // Run multi-token generation
    ReferenceResult RunGeneration(const std::vector<uint32_t>& prompt_tokens, 
                                   uint32_t max_tokens);
    
    // Get model info
    struct ModelInfo {
        uint32_t n_layers = 0;
        uint32_t n_heads = 0;
        uint32_t n_kv_heads = 0;
        uint32_t hidden_size = 0;
        uint32_t vocab_size = 0;
        uint32_t max_seq_len = 0;
    };
    ModelInfo GetModelInfo() const { return m_model_info; }
    
    // Check if initialized
    bool IsInitialized() const { return m_initialized; }
    
    // Set activation capture callback (for custom capture points)
    using ActivationCallback = std::function<void(const std::string&, uint32_t, const float*, size_t)>;
    void SetActivationCallback(ActivationCallback cb) { m_activation_callback = cb; }
    
private:
    ReferenceConfig m_config;
    ModelInfo m_model_info;
    bool m_initialized = false;
    ActivationCallback m_activation_callback;
    
    // llama.cpp context (opaque pointer)
    void* m_llama_context = nullptr;
    void* m_llama_model = nullptr;
    
    // Load model using llama.cpp
    bool LoadModel();
    
    // Tokenize input
    std::vector<int> Tokenize(const std::string& text);
    
    // Run single forward pass
    bool ForwardPass(const std::vector<int>& tokens, std::vector<float>& logits);
    
    // Capture activation from llama.cpp internal state
    void CaptureActivation(const std::string& name, uint32_t index, 
                          const float* data, size_t count);
    
    // Extract activations from llama.cpp internal structures
    void ExtractActivations(const std::vector<int>& tokens, 
                           std::vector<ReferenceActivation>& out_activations);
    
    // Helper: run llama.cpp CLI and parse output
    bool RunLlamaCLI(const std::string& args, std::string& output);
};

// Activation hook registry for llama.cpp instrumentation
class ActivationHookRegistry {
public:
    static ActivationHookRegistry& Instance();
    
    // Register a hook point
    void RegisterHook(const std::string& name, uint32_t op_index);
    
    // Check if hook should fire
    bool ShouldCapture(const std::string& name, uint32_t op_index) const;
    
    // Clear hooks
    void Clear();
    
private:
    std::unordered_map<std::string, uint32_t> m_hooks;
};

} // namespace CLI
} // namespace RawrXD