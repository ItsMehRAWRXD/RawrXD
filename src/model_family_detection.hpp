#pragma once
#ifndef RAWRXD_MODEL_FAMILY_DETECTION_HPP
#define RAWRXD_MODEL_FAMILY_DETECTION_HPP

#include <string_view>
#include <algorithm>
#include <cctype>

namespace RawrXD {

// ============================================================================
// Model Family Enum
// ============================================================================
enum class ModelFamily {
    // Unknown / Generic
    UNKNOWN = 0,
    GENERIC,
    
    // Llama family
    LLAMA2,
    LLAMA3,
    
    // Mistral family
    MISTRAL,
    MIXTRAL,
    
    // Custom models
    BIGDADDYG,      // Custom 70B Llama-2 based
    
    // Microsoft
    PHI3,
    PHI4,
    
    // Alibaba
    QWEN2,
    QWEN25,
    QWEN3,
    
    // Google
    GEMMA2,
    GEMMA3,
    
    // DeepSeek
    DEEPSEEK,
    DEEPSEEK_CODER,
    
    // Other
    CODESTRAL,
    NEMO,
    
    // Cloud models (external APIs)
    CLOUD_KIMI,
    CLOUD_NEMOTRON,
    CLOUD_GLM,
    CLOUD_DEEPSEEK,
};

// ============================================================================
// Family Detection from Model Name
// Primary method: Pattern matching on model name/ID
// ============================================================================
inline ModelFamily DetectFamilyFromName(std::string_view name) {
    // Convert to lowercase for matching
    std::string lower;
    lower.reserve(name.length());
    for (char c : name) {
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    
    // Helper lambda for checking patterns
    auto contains = [&lower](std::string_view pattern) {
        return lower.find(pattern) != std::string::npos;
    };
    
    auto starts_with = [&lower](std::string_view pattern) {
        return lower.size() >= pattern.size() && 
               lower.compare(0, pattern.size(), pattern) == 0;
    };
    
    // ============================================================================
    // PRIORITY 1: Custom models (most specific patterns first)
    // ============================================================================
    
    // BigDaddyG family - Custom 70B Llama-2 based models
    // These models use BOS + raw prompt and output [TEXT]...[END] markers
    if (contains("bigdaddyg") || 
        contains("bigdaddy") ||
        starts_with("bg-") ||
        starts_with("bg40") ||
        contains("cheetah") ||
        contains("bg-ide") ||
        contains("bg-test") ||
        contains("bg-unleashed") ||
        contains("bg-f32")) {
        return ModelFamily::BIGDADDYG;
    }
    
    // ============================================================================
    // PRIORITY 2: Cloud models (external APIs)
    // ============================================================================
    
    if (contains(":cloud")) {
        if (contains("kimi")) return ModelFamily::CLOUD_KIMI;
        if (contains("nemotron")) return ModelFamily::CLOUD_NEMOTRON;
        if (contains("glm")) return ModelFamily::CLOUD_GLM;
        if (contains("deepseek")) return ModelFamily::CLOUD_DEEPSEEK;
        return ModelFamily::GENERIC;
    }
    
    // ============================================================================
    // PRIORITY 3: Standard model families
    // ============================================================================
    
    // Phi family (Microsoft)
    if (contains("phi4") || contains("phi-4")) return ModelFamily::PHI4;
    if (contains("phi3") || contains("phi-3") || contains("phi:")) return ModelFamily::PHI3;
    
    // Llama family (Meta)
    if (contains("llama3") || contains("llama-3")) {
        // Distinguish versions
        if (contains("3.3") || contains("3_3")) return ModelFamily::LLAMA3;
        if (contains("3.2") || contains("3_2")) return ModelFamily::LLAMA3;
        if (contains("3.1") || contains("3_1")) return ModelFamily::LLAMA3;
        return ModelFamily::LLAMA3;
    }
    if (contains("llama2") || contains("llama-2")) return ModelFamily::LLAMA2;
    
    // Mistral family
    if (contains("mixtral")) return ModelFamily::MIXTRAL;
    if (contains("mistral") || contains("ministral")) return ModelFamily::MISTRAL;
    if (contains("nemo")) return ModelFamily::NEMO;
    
    // Codestral (Mistral's code model)
    if (contains("codestral")) return ModelFamily::CODESTRAL;
    
    // Dolphin (fine-tuned Mistral)
    if (contains("dolphin")) return ModelFamily::MISTRAL;
    
    // Qwen family (Alibaba)
    if (contains("qwen3") || contains("qwen-3")) return ModelFamily::QWEN3;
    if (contains("qwen2.5") || contains("qwen-2.5")) return ModelFamily::QWEN25;
    if (contains("qwen2") || contains("qwen-2")) return ModelFamily::QWEN2;
    if (contains("qwen")) return ModelFamily::QWEN25; // Default to 2.5
    
    // Gemma family (Google)
    if (contains("gemma3") || contains("gemma-3")) return ModelFamily::GEMMA3;
    if (contains("gemma2") || contains("gemma-2")) return ModelFamily::GEMMA2;
    if (contains("gemma")) return ModelFamily::GEMMA2;
    
    // DeepSeek family
    if (contains("deepseek-coder")) return ModelFamily::DEEPSEEK_CODER;
    if (contains("deepseek")) return ModelFamily::DEEPSEEK;
    
    // CodeLlama (Meta)
    if (contains("codellama")) return ModelFamily::LLAMA2;
    
    // ============================================================================
    // PRIORITY 4: Fallback
    // ============================================================================
    
    return ModelFamily::UNKNOWN;
}

// ============================================================================
// Family Detection from GGUF Metadata
// Secondary method: Use actual file metadata when available
// ============================================================================
struct GGUFMetadataHints {
    std::string architecture;
    std::string chat_template;
    uint32_t vocab_size = 0;
    uint32_t context_length = 0;
    std::string model_name;
};

inline ModelFamily DetectFamilyFromMetadata(const GGUFMetadataHints& hints) {
    // Convert to lowercase
    auto tolower = [](std::string_view sv) {
        std::string result;
        result.reserve(sv.length());
        for (char c : sv) {
            result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        return result;
    };
    
    std::string arch = tolower(hints.architecture);
    std::string name = tolower(hints.model_name);
    std::string tmpl = tolower(hints.chat_template);
    
    // Check model name first (most reliable for custom models)
    if (name.find("bigdaddyg") != std::string::npos ||
        name.find("bigdaddy") != std::string::npos) {
        return ModelFamily::BIGDADDYG;
    }
    
    // Check architecture
    if (arch == "llama") {
        // Distinguish llama2 vs llama3 by vocab size
        if (hints.vocab_size == 128256 || hints.vocab_size == 128000) {
            return ModelFamily::LLAMA3;
        }
        if (hints.vocab_size == 32000 || hints.context_length <= 4096) {
            return ModelFamily::LLAMA2;
        }
        return ModelFamily::LLAMA3; // Default to newer
    }
    
    if (arch == "phi3") return ModelFamily::PHI3;
    if (arch == "qwen2") return ModelFamily::QWEN2;
    if (arch == "gemma") return ModelFamily::GEMMA2;
    if (arch == "mistral") return ModelFamily::MISTRAL;
    if (arch == "mixtral") return ModelFamily::MIXTRAL;
    
    // Check chat template patterns
    if (tmpl.find("[INST]") != std::string::npos) {
        return ModelFamily::MISTRAL;
    }
    if (tmpl.find("<|user|>") != std::string::npos) {
        return ModelFamily::PHI3;
    }
    if (tmpl.find("<|begin_of_text|>") != std::string::npos) {
        return ModelFamily::LLAMA3;
    }
    if (tmpl.find("<|im_start|>") != std::string::npos) {
        return ModelFamily::QWEN25;
    }
    if (tmpl.find("<start_of_turn>") != std::string::npos) {
        return ModelFamily::GEMMA2;
    }
    
    // Fallback to name-based detection
    return DetectFamilyFromName(hints.model_name);
}

// ============================================================================
// Family Properties
// Get configuration for a family
// ============================================================================
struct FamilyConfig {
    const char* name;
    const char* prompt_template;  // Description
    const char* output_parser;    // Parser type
    bool supports_system_prompt;
    bool supports_tools;
    uint32_t default_context;
};

inline FamilyConfig GetFamilyConfig(ModelFamily family) {
    switch (family) {
        case ModelFamily::BIGDADDYG:
            return {
                "bigdaddyg",
                "raw_bos",           // <s> + raw prompt
                "text_markers",      // [TEXT]...[END]
                false,               // No system prompt support
                false,               // No tool support
                4096
            };
            
        case ModelFamily::LLAMA2:
            return {
                "llama2",
                "mistral_llama2",    // [INST] ... [/INST]
                "plain",
                true,
                false,
                4096
            };
            
        case ModelFamily::LLAMA3:
            return {
                "llama3",
                "llama3",            // <|begin_of_text|> ... <|eot_id|>
                "plain",
                true,
                true,
                8192
            };
            
        case ModelFamily::MISTRAL:
        case ModelFamily::MIXTRAL:
            return {
                "mistral",
                "mistral_llama2",    // [INST] ... [/INST]
                "plain",
                true,
                true,
                32768
            };
            
        case ModelFamily::PHI3:
            return {
                "phi3",
                "phi3",              // <|user|> ... <|assistant|>
                "plain",
                true,
                true,
                4096
            };
            
        case ModelFamily::PHI4:
            return {
                "phi4",
                "phi3",              // Same as Phi-3
                "plain",
                true,
                true,
                16384
            };
            
        case ModelFamily::QWEN2:
        case ModelFamily::QWEN25:
            return {
                "qwen",
                "chatml",            // <|im_start|> ... <|im_end|>
                "plain",
                true,
                true,
                32768
            };
            
        case ModelFamily::QWEN3:
            return {
                "qwen3",
                "chatml",
                "plain",
                true,
                true,
                128000
            };
            
        case ModelFamily::GEMMA2:
        case ModelFamily::GEMMA3:
            return {
                "gemma",
                "gemma",             // <start_of_turn> ... <end_of_turn>
                "plain",
                true,
                false,
                8192
            };
            
        case ModelFamily::DEEPSEEK:
        case ModelFamily::DEEPSEEK_CODER:
            return {
                "deepseek",
                "chatml",
                "thinking",          // <think>...</think>
                true,
                true,
                65536
            };
            
        case ModelFamily::CODESTRAL:
            return {
                "codestral",
                "mistral_llama2",
                "code_blocks",       // Extract ```code```
                true,
                false,
                32768
            };
            
        default:
            return {
                "unknown",
                "generic",
                "plain",
                true,
                false,
                4096
            };
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

inline const char* FamilyToString(ModelFamily family) {
    return GetFamilyConfig(family).name;
}

inline bool FamilySupportsSystemPrompt(ModelFamily family) {
    return GetFamilyConfig(family).supports_system_prompt;
}

inline bool FamilySupportsTools(ModelFamily family) {
    return GetFamilyConfig(family).supports_tools;
}

} // namespace RawrXD

#endif // RAWRXD_MODEL_FAMILY_DETECTION_HPP
