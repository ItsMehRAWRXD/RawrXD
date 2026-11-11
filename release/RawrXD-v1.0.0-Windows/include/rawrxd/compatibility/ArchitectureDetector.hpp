#pragma once

#include <string>
#include <memory>
#include <unordered_map>
#include <vector>

namespace rawrxd {
namespace compatibility {

enum class ModelArchitecture {
    UNKNOWN,
    LLAMA,           // Llama 1/2/3, Mistral, Mixtral
    LLAMA3,          // Llama 3.x specific
    MISTRAL,         // Mistral 7B
    MIXTRAL,         // Mixtral 8x7B, 8x22B
    PHI,             // Phi-1/2/3
    PHI3,            // Phi-3 specific
    QWEN,            // Qwen 1/2/2.5
    QWEN2,           // Qwen 2.x
    DEEPSEEK,        // DeepSeek
    CODELLAMA,       // CodeLlama variants
    CODESTRAL,       // Codestral
    GEMMA,           // Gemma 1/2
    GEMMA2,          // Gemma 2 specific
    STABLELM,        // StableLM
    FALCON,          // Falcon
    GPTNEOX,         // GPT-NeoX/Pythia
    GPT2,            // GPT-2
    GPTJ,            // GPT-J
    MPT,             // MPT
    REFACT,          // Refact
    STARCODER,       // StarCoder
    PERSIMMON,       // Persimmon
    BLOOM,           // BLOOM
    GPTBIGCODE,      // GPT-BigCode
    COMMAND_R,       // Cohere Command-R
    DBRX,            // DBRX
    XVERSE,          // XVERSE
    ORION,           // Orion
    MINICPM,         // MiniCPM
    BAICHUAN,        // Baichuan
    YI,              // Yi
    INTERNLM,        // InternLM
    SOLAR            // Solar
};

struct ModelConfig {
    ModelArchitecture arch;
    std::string name;
    int vocab_size;
    int hidden_size;
    int num_layers;
    int num_heads;
    int num_kv_heads;
    int head_dim;
    int intermediate_size;
    float rope_theta;
    float rope_scaling;
    bool use_gqa;              // Grouped Query Attention
    bool use_sliding_window;
    int sliding_window;
    bool use_alibi;
    bool use_rope;
    bool use_qk_norm;
    bool use_parallel_residual;
    std::string rope_scaling_type;
    std::string norm_type;     // rmsnorm, layernorm
    std::string activation;    // silu, gelu, relu, etc.
    std::string attention_type; // standard, flash, xformers
    std::unordered_map<std::string, std::string> extra_params;
};

class ArchitectureDetector {
public:
    ArchitectureDetector();
    ~ArchitectureDetector() = default;

    // Detect architecture from GGUF metadata
    ModelArchitecture DetectFromGGUF(const std::string& gguf_path);
    ModelArchitecture DetectFromMetadata(const std::unordered_map<std::string, std::string>& metadata);
    
    // Get configuration for detected architecture
    ModelConfig GetConfig(ModelArchitecture arch);
    ModelConfig GetConfig(const std::string& model_name);
    
    // Validate model compatibility
    bool IsSupported(ModelArchitecture arch);
    bool IsSupported(const std::string& model_name);
    
    // Get supported architectures list
    std::vector<ModelArchitecture> GetSupportedArchitectures();
    std::vector<std::string> GetSupportedModelNames();
    
    // Architecture-specific feature checks
    bool SupportsVision(ModelArchitecture arch);
    bool SupportsFunctionCalling(ModelArchitecture arch);
    bool SupportsToolUse(ModelArchitecture arch);
    bool RequiresSpecialTokenizer(ModelArchitecture arch);
    
    // Get architecture name
    std::string GetArchitectureName(ModelArchitecture arch);
    ModelArchitecture ParseArchitectureName(const std::string& name);

private:
    void InitializeArchitectureConfigs();
    void InitializeModelMappings();
    
    std::unordered_map<ModelArchitecture, ModelConfig> configs_;
    std::unordered_map<std::string, ModelArchitecture> model_mappings_;
    std::unordered_map<std::string, ModelArchitecture> family_mappings_;
};

// Architecture-specific kernel selectors
class KernelSelector {
public:
    // Select optimal kernels for architecture
    static std::string SelectAttentionKernel(ModelArchitecture arch, int seq_len);
    static std::string SelectFFNKernel(ModelArchitecture arch, int hidden_size);
    static std::string SelectNormKernel(ModelArchitecture arch, const std::string& norm_type);
    static std::string SelectRoPEKernel(ModelArchitecture arch, int head_dim);
    
    // Check if fused kernels available
    static bool HasFusedAttention(ModelArchitecture arch);
    static bool HasFusedFFN(ModelArchitecture arch);
    static bool HasOptimizedRoPE(ModelArchitecture arch);
};

} // namespace compatibility
} // namespace rawrxd
