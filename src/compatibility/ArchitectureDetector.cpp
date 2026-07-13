#include "rawrxd/compatibility/ArchitectureDetector.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <regex>

namespace rawrxd {
namespace compatibility {

ArchitectureDetector::ArchitectureDetector() {
    InitializeArchitectureConfigs();
    InitializeModelMappings();
}

void ArchitectureDetector::InitializeArchitectureConfigs() {
    // LLaMA 3.x configuration
    configs_[ModelArchitecture::LLAMA3] = {
        .arch = ModelArchitecture::LLAMA3,
        .name = "llama3",
        .vocab_size = 128256,
        .hidden_size = 4096,
        .num_layers = 32,
        .num_heads = 32,
        .num_kv_heads = 8,  // GQA
        .head_dim = 128,
        .intermediate_size = 14336,
        .rope_theta = 500000.0f,
        .rope_scaling = 1.0f,
        .use_gqa = true,
        .use_sliding_window = false,
        .sliding_window = 0,
        .use_alibi = false,
        .use_rope = true,
        .use_qk_norm = true,
        .use_parallel_residual = false,
        .rope_scaling_type = "llama3",
        .norm_type = "rmsnorm",
        .activation = "silu",
        .attention_type = "flash"
    };
    
    // Mistral 7B configuration
    configs_[ModelArchitecture::MISTRAL] = {
        .arch = ModelArchitecture::MISTRAL,
        .name = "mistral",
        .vocab_size = 32000,
        .hidden_size = 4096,
        .num_layers = 32,
        .num_heads = 32,
        .num_kv_heads = 8,  // GQA
        .head_dim = 128,
        .intermediate_size = 14336,
        .rope_theta = 10000.0f,
        .rope_scaling = 1.0f,
        .use_gqa = true,
        .use_sliding_window = true,
        .sliding_window = 4096,
        .use_alibi = false,
        .use_rope = true,
        .use_qk_norm = false,
        .use_parallel_residual = false,
        .rope_scaling_type = "",
        .norm_type = "rmsnorm",
        .activation = "silu",
        .attention_type = "flash"
    };
    
    // Mixtral 8x7B configuration
    configs_[ModelArchitecture::MIXTRAL] = {
        .arch = ModelArchitecture::MIXTRAL,
        .name = "mixtral",
        .vocab_size = 32000,
        .hidden_size = 4096,
        .num_layers = 32,
        .num_heads = 32,
        .num_kv_heads = 8,
        .head_dim = 128,
        .intermediate_size = 14336,
        .rope_theta = 10000.0f,
        .rope_scaling = 1.0f,
        .use_gqa = true,
        .use_sliding_window = true,
        .sliding_window = 4096,
        .use_alibi = false,
        .use_rope = true,
        .use_qk_norm = false,
        .use_parallel_residual = false,
        .rope_scaling_type = "",
        .norm_type = "rmsnorm",
        .activation = "silu",
        .attention_type = "flash"
    };
    
    // Mixtral 8x22B configuration
    configs_[ModelArchitecture::MIXTRAL].extra_params["num_experts"] = "8";
    configs_[ModelArchitecture::MIXTRAL].extra_params["num_active_experts"] = "2";
    configs_[ModelArchitecture::MIXTRAL].extra_params["expert_capacity"] = "8192";
    
    // Phi-3 configuration
    configs_[ModelArchitecture::PHI3] = {
        .arch = ModelArchitecture::PHI3,
        .name = "phi3",
        .vocab_size = 32064,
        .hidden_size = 3072,
        .num_layers = 32,
        .num_heads = 32,
        .num_kv_heads = 32,
        .head_dim = 96,
        .intermediate_size = 8192,
        .rope_theta = 10000.0f,
        .rope_scaling = 1.0f,
        .use_gqa = false,
        .use_sliding_window = true,
        .sliding_window = 2047,
        .use_alibi = false,
        .use_rope = true,
        .use_qk_norm = false,
        .use_parallel_residual = true,
        .rope_scaling_type = "long_rope",
        .norm_type = "rmsnorm",
        .activation = "silu",
        .attention_type = "flash"
    };
    
    // Qwen2.5 configuration
    configs_[ModelArchitecture::QWEN2] = {
        .arch = ModelArchitecture::QWEN2,
        .name = "qwen2",
        .vocab_size = 151936,
        .hidden_size = 4096,
        .num_layers = 32,
        .num_heads = 32,
        .num_kv_heads = 8,  // GQA
        .head_dim = 128,
        .intermediate_size = 11008,
        .rope_theta = 1000000.0f,
        .rope_scaling = 1.0f,
        .use_gqa = true,
        .use_sliding_window = false,
        .sliding_window = 0,
        .use_alibi = false,
        .use_rope = true,
        .use_qk_norm = false,
        .use_parallel_residual = false,
        .rope_scaling_type = "yarn",
        .norm_type = "rmsnorm",
        .activation = "silu",
        .attention_type = "flash"
    };
    
    // DeepSeek configuration
    configs_[ModelArchitecture::DEEPSEEK] = {
        .arch = ModelArchitecture::DEEPSEEK,
        .name = "deepseek",
        .vocab_size = 102400,
        .hidden_size = 4096,
        .num_layers = 32,
        .num_heads = 32,
        .num_kv_heads = 32,
        .head_dim = 128,
        .intermediate_size = 11008,
        .rope_theta = 10000.0f,
        .rope_scaling = 1.0f,
        .use_gqa = false,
        .use_sliding_window = false,
        .sliding_window = 0,
        .use_alibi = true,
        .use_rope = false,
        .use_qk_norm = false,
        .use_parallel_residual = false,
        .rope_scaling_type = "",
        .norm_type = "rmsnorm",
        .activation = "silu",
        .attention_type = "standard"
    };
    
    // Codestral configuration
    configs_[ModelArchitecture::CODESTRAL] = {
        .arch = ModelArchitecture::CODESTRAL,
        .name = "codestral",
        .vocab_size = 32064,
        .hidden_size = 6144,
        .num_layers = 48,
        .num_heads = 48,
        .num_kv_heads = 8,  // GQA
        .head_dim = 128,
        .intermediate_size = 24576,
        .rope_theta = 1000000.0f,
        .rope_scaling = 1.0f,
        .use_gqa = true,
        .use_sliding_window = true,
        .sliding_window = 32768,
        .use_alibi = false,
        .use_rope = true,
        .use_qk_norm = false,
        .use_parallel_residual = false,
        .rope_scaling_type = "",
        .norm_type = "rmsnorm",
        .activation = "silu",
        .attention_type = "flash"
    };
    
    // Gemma 2 configuration
    configs_[ModelArchitecture::GEMMA2] = {
        .arch = ModelArchitecture::GEMMA2,
        .name = "gemma2",
        .vocab_size = 256000,
        .hidden_size = 3584,
        .num_layers = 28,
        .num_heads = 16,
        .num_kv_heads = 16,
        .head_dim = 256,
        .intermediate_size = 14336,
        .rope_theta = 10000.0f,
        .rope_scaling = 1.0f,
        .use_gqa = false,
        .use_sliding_window = true,
        .sliding_window = 4096,
        .use_alibi = false,
        .use_rope = true,
        .use_qk_norm = true,
        .use_parallel_residual = false,
        .rope_scaling_type = "",
        .norm_type = "rmsnorm",
        .activation = "gelu",
        .attention_type = "flash"
    };
}

void ArchitectureDetector::InitializeModelMappings() {
    // LLaMA family
    model_mappings_["llama"] = ModelArchitecture::LLAMA;
    model_mappings_["llama-2"] = ModelArchitecture::LLAMA;
    model_mappings_["llama-3"] = ModelArchitecture::LLAMA3;
    model_mappings_["llama-3.1"] = ModelArchitecture::LLAMA3;
    model_mappings_["llama-3.2"] = ModelArchitecture::LLAMA3;
    
    // Mistral family
    model_mappings_["mistral"] = ModelArchitecture::MISTRAL;
    model_mappings_["mistral-7b"] = ModelArchitecture::MISTRAL;
    model_mappings_["mixtral"] = ModelArchitecture::MIXTRAL;
    model_mappings_["mixtral-8x7b"] = ModelArchitecture::MIXTRAL;
    model_mappings_["mixtral-8x22b"] = ModelArchitecture::MIXTRAL;
    
    // Phi family
    model_mappings_["phi"] = ModelArchitecture::PHI;
    model_mappings_["phi-2"] = ModelArchitecture::PHI;
    model_mappings_["phi-3"] = ModelArchitecture::PHI3;
    model_mappings_["phi-3.5"] = ModelArchitecture::PHI3;
    
    // Qwen family
    model_mappings_["qwen"] = ModelArchitecture::QWEN;
    model_mappings_["qwen2"] = ModelArchitecture::QWEN2;
    model_mappings_["qwen2.5"] = ModelArchitecture::QWEN2;
    
    // DeepSeek
    model_mappings_["deepseek"] = ModelArchitecture::DEEPSEEK;
    model_mappings_["deepseek-coder"] = ModelArchitecture::DEEPSEEK;
    
    // Code models
    model_mappings_["codellama"] = ModelArchitecture::CODELLAMA;
    model_mappings_["codestral"] = ModelArchitecture::CODESTRAL;
    model_mappings_["starcoder"] = ModelArchitecture::STARCODER;
    model_mappings_["starcoder2"] = ModelArchitecture::STARCODER;
    
    // Gemma
    model_mappings_["gemma"] = ModelArchitecture::GEMMA;
    model_mappings_["gemma-2"] = ModelArchitecture::GEMMA2;
    model_mappings_["gemma2"] = ModelArchitecture::GEMMA2;
    
    // Family mappings for pattern matching
    family_mappings_["llama"] = ModelArchitecture::LLAMA;
    family_mappings_["mistral"] = ModelArchitecture::MISTRAL;
    family_mappings_["mixtral"] = ModelArchitecture::MIXTRAL;
    family_mappings_["phi"] = ModelArchitecture::PHI;
    family_mappings_["qwen"] = ModelArchitecture::QWEN;
    family_mappings_["deepseek"] = ModelArchitecture::DEEPSEEK;
    family_mappings_["gemma"] = ModelArchitecture::GEMMA;
}

ModelArchitecture ArchitectureDetector::DetectFromMetadata(
    const std::unordered_map<std::string, std::string>& metadata) {
    
    // Check for explicit architecture field
    auto arch_it = metadata.find("general.architecture");
    if (arch_it != metadata.end()) {
        std::string arch_name = arch_it->second;
        std::transform(arch_name.begin(), arch_name.end(), arch_name.begin(), ::tolower);
        
        auto it = model_mappings_.find(arch_name);
        if (it != model_mappings_.end()) {
            return it->second;
        }
        
        // Try family matching
        for (const auto& [family, arch] : family_mappings_) {
            if (arch_name.find(family) != std::string::npos) {
                return arch;
            }
        }
    }
    
    // Check model name/basename
    auto name_it = metadata.find("general.name");
    if (name_it != metadata.end()) {
        std::string name = name_it->second;
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        
        for (const auto& [model, arch] : model_mappings_) {
            if (name.find(model) != std::string::npos) {
                return arch;
            }
        }
    }
    
    // Infer from hyperparameters
    auto vocab_it = metadata.find("llama.vocab_size");
    auto hidden_it = metadata.find("llama.hidden_size");
    auto layers_it = metadata.find("llama.block_count");
    
    if (vocab_it != metadata.end() && hidden_it != metadata.end()) {
        int vocab_size = std::stoi(vocab_it->second);
        int hidden_size = std::stoi(hidden_it->second);
        
        // Heuristic detection based on known configurations
        if (vocab_size == 128256 && hidden_size == 4096) {
            return ModelArchitecture::LLAMA3;
        }
        if (vocab_size == 32000 && hidden_size == 4096) {
            return ModelArchitecture::MISTRAL;
        }
        if (vocab_size == 32064 && hidden_size == 3072) {
            return ModelArchitecture::PHI3;
        }
        if (vocab_size == 151936) {
            return ModelArchitecture::QWEN2;
        }
        if (vocab_size == 256000) {
            return ModelArchitecture::GEMMA2;
        }
    }
    
    return ModelArchitecture::UNKNOWN;
}

ModelConfig ArchitectureDetector::GetConfig(ModelArchitecture arch) {
    auto it = configs_.find(arch);
    if (it != configs_.end()) {
        return it->second;
    }
    return configs_[ModelArchitecture::LLAMA3];  // Default fallback
}

bool ArchitectureDetector::IsSupported(ModelArchitecture arch) {
    return arch != ModelArchitecture::UNKNOWN && 
           configs_.find(arch) != configs_.end();
}

std::string ArchitectureDetector::GetArchitectureName(ModelArchitecture arch) {
    switch (arch) {
        case ModelArchitecture::LLAMA: return "llama";
        case ModelArchitecture::LLAMA3: return "llama3";
        case ModelArchitecture::MISTRAL: return "mistral";
        case ModelArchitecture::MIXTRAL: return "mixtral";
        case ModelArchitecture::PHI: return "phi";
        case ModelArchitecture::PHI3: return "phi3";
        case ModelArchitecture::QWEN: return "qwen";
        case ModelArchitecture::QWEN2: return "qwen2";
        case ModelArchitecture::DEEPSEEK: return "deepseek";
        case ModelArchitecture::CODESTRAL: return "codestral";
        case ModelArchitecture::GEMMA: return "gemma";
        case ModelArchitecture::GEMMA2: return "gemma2";
        default: return "unknown";
    }
}

std::vector<ModelArchitecture> ArchitectureDetector::GetSupportedArchitectures() {
    std::vector<ModelArchitecture> result;
    for (const auto& [arch, config] : configs_) {
        result.push_back(arch);
    }
    return result;
}

// KernelSelector implementations
std::string KernelSelector::SelectAttentionKernel(ModelArchitecture arch, int seq_len) {
    switch (arch) {
        case ModelArchitecture::LLAMA3:
        case ModelArchitecture::MISTRAL:
        case ModelArchitecture::MIXTRAL:
            return seq_len > 4096 ? "flash_attention_v2" : "flash_attention";
        case ModelArchitecture::PHI3:
            return "phi_flash_attention";
        case ModelArchitecture::QWEN2:
            return "qwen_flash_attention";
        default:
            return "standard_attention";
    }
}

bool KernelSelector::HasFusedAttention(ModelArchitecture arch) {
    return arch == ModelArchitecture::LLAMA3 ||
           arch == ModelArchitecture::MISTRAL ||
           arch == ModelArchitecture::MIXTRAL ||
           arch == ModelArchitecture::PHI3 ||
           arch == ModelArchitecture::QWEN2;
}

} // namespace compatibility
} // namespace rawrxd
