#include "rawrxd/compatibility/ModelCapabilities.hpp"
#include "rawrxd/compatibility/ArchitectureDetector.hpp"
#include <unordered_map>

namespace rawrxd {
namespace compatibility {

ModelCapabilities CapabilityDetector::DetectFromConfig(const ModelConfig& config) {
    ModelCapabilities caps;
    
    // Position encoding
    caps.usesRope = config.use_rope;
    caps.usesAlibi = config.use_alibi;
    caps.usesAbsolute = !config.use_rope && !config.use_alibi;
    
    // RoPE variants from extra params
    auto it = config.extra_params.find("rope_scaling_type");
    if (it != config.extra_params.end()) {
        if (it->second == "yarn") caps.usesYarn = true;
        else if (it->second == "long_rope") caps.usesLongRope = true;
        else if (it->second == "ntk") caps.usesNTKScaling = true;
        else if (it->second == "dynamic") caps.usesDynamicScaling = true;
    }
    
    // Check for long context support
    if (config.max_position_embeddings > 32768) {
        caps.supportsLongContext = true;
    }
    caps.maxContextLength = config.max_position_embeddings;
    
    // Attention mechanisms
    caps.usesSlidingWindow = config.use_sliding_window;
    caps.usesGQA = config.use_gqa;
    caps.usesMQA = (config.num_kv_heads == 1);
    caps.slidingWindowSize = config.sliding_window;
    
    // Architecture features
    it = config.extra_params.find("use_qk_norm");
    if (it != config.extra_params.end() && it->second == "true") {
        caps.usesQKNorm = true;
    }
    
    it = config.extra_params.find("use_parallel_ffn");
    if (it != config.extra_params.end() && it->second == "true") {
        caps.usesParallelFFN = true;
    }
    
    // MoE detection
    it = config.extra_params.find("num_experts");
    if (it != config.extra_params.end()) {
        int num_experts = std::stoi(it->second);
        if (num_experts > 1) {
            caps.usesMoE = true;
        }
    }
    
    // Normalization type
    it = config.extra_params.find("norm_type");
    if (it != config.extra_params.end()) {
        if (it->second == "pre") caps.usesPreNorm = true;
        else if (it->second == "post") caps.usesPostNorm = true;
    } else {
        caps.usesPreNorm = true;  // Default for most modern models
    }
    
    // Tokenization (inferred from architecture)
    switch (config.arch) {
        case ModelArchitecture::LLAMA3:
        case ModelArchitecture::CODESTRAL:
            caps.usesTiktoken = true;
            caps.usesByteFallback = true;
            break;
        case ModelArchitecture::MISTRAL:
        case ModelArchitecture::MIXTRAL:
            caps.usesSentencePiece = true;
            caps.usesBPE = true;
            break;
        case ModelArchitecture::PHI3:
            caps.usesBPE = true;
            break;
        case ModelArchitecture::GEMMA2:
        case ModelArchitecture::GEMMA:
            caps.usesSentencePiece = true;
            break;
        default:
            caps.usesBPE = true;
            break;
    }
    
    // Quantization support (most models support all)
    caps.supportsQ4 = true;
    caps.supportsQ5 = true;
    caps.supportsQ6 = true;
    caps.supportsQ8 = true;
    caps.supportsFP16 = true;
    caps.supportsINT8 = false;  // Requires calibration
    
    return caps;
}

std::vector<std::string> CapabilityDetector::ValidateCapabilities(const ModelCapabilities& caps) {
    std::vector<std::string> issues;
    
    // Check for conflicting position encodings
    int pos_encodings = 0;
    if (caps.usesRope) pos_encodings++;
    if (caps.usesAlibi) pos_encodings++;
    if (caps.usesAbsolute) pos_encodings++;
    
    if (pos_encodings > 1) {
        issues.push_back("Multiple position encodings detected");
    }
    if (pos_encodings == 0) {
        issues.push_back("No position encoding specified");
    }
    
    // Check for conflicting attention types
    if (caps.usesGQA && caps.usesMQA) {
        issues.push_back("Both GQA and MQA specified");
    }
    
    // Check context length
    if (caps.maxContextLength <= 0) {
        issues.push_back("Invalid context length");
    }
    if (caps.maxContextLength > 200000) {
        issues.push_back("Very long context - may require excessive memory");
    }
    
    // Check sliding window
    if (caps.usesSlidingWindow && caps.slidingWindowSize <= 0) {
        issues.push_back("Sliding window enabled but size not specified");
    }
    
    // Check MoE
    if (caps.usesMoE) {
        issues.push_back("MoE requires special routing implementation");
    }
    
    return issues;
}

std::vector<std::string> CapabilityDetector::GetRequiredKernels(const ModelCapabilities& caps) {
    std::vector<std::string> kernels;
    
    // Attention kernels
    if (caps.usesGQA) {
        if (caps.usesSlidingWindow) {
            kernels.push_back("flash_attention_gqa_sliding");
        } else {
            kernels.push_back("flash_attention_gqa");
        }
    } else if (caps.usesMQA) {
        kernels.push_back("flash_attention_mqa");
    } else {
        kernels.push_back("flash_attention");
    }
    
    // RoPE kernels
    if (caps.usesYarn) {
        kernels.push_back("rope_yarn");
    } else if (caps.usesLongRope) {
        kernels.push_back("rope_long");
    } else if (caps.usesNTKScaling) {
        kernels.push_back("rope_ntk");
    } else if (caps.usesRope) {
        kernels.push_back("rope_standard");
    }
    
    // ALiBi kernel
    if (caps.usesAlibi) {
        kernels.push_back("alibi_attention");
    }
    
    // MoE kernels
    if (caps.usesMoE) {
        kernels.push_back("moe_routing");
        kernels.push_back("moe_expert_compute");
    }
    
    // Standard kernels
    kernels.push_back("rms_norm");
    kernels.push_back("silu_activation");
    kernels.push_back("matmul_quantized");
    
    return kernels;
}

bool CapabilityDetector::IsSupported(const ModelCapabilities& caps) {
    // Check for unsupported features
    if (caps.usesAlibi) {
        // ALiBi is supported but may have limitations
    }
    
    if (caps.usesYarn) {
        // YaRN is supported
    }
    
    if (caps.usesMoE) {
        // MoE is supported
    }
    
    // All other features are supported
    return true;
}

// CapabilityKernelSelector implementation
std::string CapabilityKernelSelector::SelectAttentionKernel(const ModelCapabilities& caps) {
    if (caps.usesAlibi) {
        return "flash_attention_alibi";
    }
    
    if (caps.usesGQA) {
        if (caps.usesSlidingWindow) {
            return "flash_attention_gqa_sliding_window";
        }
        return "flash_attention_gqa";
    }
    
    if (caps.usesMQA) {
        return "flash_attention_mqa";
    }
    
    if (caps.usesSlidingWindow) {
        return "flash_attention_sliding_window";
    }
    
    return "flash_attention";
}

std::string CapabilityKernelSelector::SelectRoPEKernel(const ModelCapabilities& caps) {
    if (caps.usesYarn) {
        return "rope_yarn_fused";
    }
    if (caps.usesLongRope) {
        return "rope_long_fused";
    }
    if (caps.usesNTKScaling) {
        return "rope_ntk_fused";
    }
    if (caps.usesDynamicScaling) {
        return "rope_dynamic_fused";
    }
    if (caps.usesRope) {
        return "rope_standard_fused";
    }
    return "none";
}

std::string CapabilityKernelSelector::SelectMatMulKernel(const ModelCapabilities& caps) {
    if (caps.supportsLongContext && caps.maxContextLength > 65536) {
        return "matmul_avx512_large_batch";
    }
    return "matmul_avx512";
}

std::string CapabilityKernelSelector::SelectFFNKernel(const ModelCapabilities& caps) {
    if (caps.usesParallelFFN) {
        return "ffn_parallel_fused";
    }
    if (caps.usesMoE) {
        return "ffn_moe_routed";
    }
    return "ffn_gated_silu";
}

KernelConfig CapabilityKernelSelector::BuildKernelConfig(const ModelCapabilities& caps) {
    KernelConfig config;
    config.attention_kernel = SelectAttentionKernel(caps);
    config.rope_kernel = SelectRoPEKernel(caps);
    config.matmul_kernel = SelectMatMulKernel(caps);
    config.activation_kernel = SelectFFNKernel(caps);
    
    // Add capability flags
    config.use_sliding_window = caps.usesSlidingWindow;
    config.use_gqa = caps.usesGQA;
    config.window_size = caps.slidingWindowSize;
    
    return config;
}

} // namespace compatibility
} // namespace rawrxd
