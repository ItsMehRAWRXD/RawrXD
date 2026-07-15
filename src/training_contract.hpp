#pragma once
#ifndef RAWRXD_TRAINING_CONTRACT_HPP
#define RAWRXD_TRAINING_CONTRACT_HPP

#include <string_view>
#include <cstdint>

namespace RawrXD {

// ============================================================================
// Training Origin Types
// Distinguish between external and internal models
// ============================================================================
enum class TrainingOrigin {
    UNKNOWN = 0,
    EXTERNAL_HF,          // HuggingFace download
    EXTERNAL_OLLAMA,        // Ollama registry
    INTERNAL_POWERSHELL,    // Your PowerShell pipeline
    INTERNAL_CUSTOM,        // Other internal training
};

// ============================================================================
// Training Contract for Internally-Trained Models
// Authoritative specification - not detected, but known
// ============================================================================
struct TrainingContract {
    // Identification
    std::string_view family_name;
    std::string_view version;
    TrainingOrigin origin;
    
    // Prompt Specification
    std::string_view bos_token;           // e.g., "<s>"
    std::string_view eos_token;           // e.g., "</s>"
    bool uses_system_prompt;              // false for BigDaddyG
    std::string_view prompt_format;       // "raw_bos", "chatml", etc.
    
    // Output Specification  
    std::string_view output_protocol;     // "text_markers", "raw", etc.
    std::string_view output_start_marker; // "[TEXT]"
    std::string_view output_end_marker;   // "[END]"
    std::string_view thinking_prefix;     // "..." or "<think>"
    
    // Tokenization
    uint32_t vocab_size;
    uint32_t context_length;
    std::string_view tokenizer_type;      // "sentencepiece", "bpe", etc.
    
    // Stop Sequences
    std::initializer_list<std::string_view> stop_sequences;
    
    // Validation
    bool IsValid() const { return !family_name.empty() && origin != TrainingOrigin::UNKNOWN; }
};

// ============================================================================
// BigDaddyG Training Contract (PowerShell Pipeline)
// Authoritative specification
// ============================================================================
inline constexpr TrainingContract BigDaddyG_Contract_v1 = {
    // Identification
    .family_name = "bigdaddyg",
    .version = "1.0",
    .origin = TrainingOrigin::INTERNAL_POWERSHELL,
    
    // Prompt Specification
    .bos_token = "<s>",
    .eos_token = "</s>",
    .uses_system_prompt = false,           // Training: no system prompts
    .prompt_format = "raw_bos",            // <s> + raw user prompt
    
    // Output Specification
    .output_protocol = "text_markers",     // [TEXT] content [END]
    .output_start_marker = "[TEXT]",
    .output_end_marker = "[END]",
    .thinking_prefix = "...",              // Sometimes emits ... prefix
    
    // Tokenization
    .vocab_size = 50000,                   // Custom vocab
    .context_length = 8192,
    .tokenizer_type = "sentencepiece",
    
    // Stop Sequences
    .stop_sequences = { "[END]", "[/TEXT]", "<s>", "</s>" },
};

// ============================================================================
// Contract Registry
// Maps internal model names to their authoritative contracts
// ============================================================================
class TrainingContractRegistry {
public:
    // Get contract for a model (returns nullptr if not an internal model)
    static const TrainingContract* GetContract(std::string_view model_name);
    
    // Check if model is internal (has training contract)
    static bool IsInternalModel(std::string_view model_name);
    
    // Register a custom contract
    static void RegisterContract(std::string_view pattern, const TrainingContract* contract);

private:
    // Built-in internal models
    static bool MatchesBigDaddyG(std::string_view name);
};

// ============================================================================
// Implementation
// ============================================================================

inline bool TrainingContractRegistry::IsInternalModel(std::string_view model_name) {
    return MatchesBigDaddyG(model_name);
}

inline const TrainingContract* TrainingContractRegistry::GetContract(std::string_view model_name) {
    if (MatchesBigDaddyG(model_name)) {
        return &BigDaddyG_Contract_v1;
    }
    return nullptr;
}

inline bool TrainingContractRegistry::MatchesBigDaddyG(std::string_view name) {
    // Convert to lowercase for matching
    auto tolower = [](char c) -> char {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    };
    
    std::string lower;
    lower.reserve(name.length());
    for (char c : name) {
        lower.push_back(tolower(c));
    }
    
    // Exact matches for BigDaddyG family
    return lower.find("bigdaddyg") != std::string::npos ||
           lower.find("bigdaddy") != std::string::npos ||
           (lower.size() >= 3 && lower.substr(0, 3) == "bg-") ||
           (lower.size() >= 4 && lower.substr(0, 4) == "bg40") ||
           lower.find("cheetah") != std::string::npos ||
           lower.find("bg-ide") != std::string::npos ||
           lower.find("bg-test") != std::string::npos ||
           lower.find("bg-unleashed") != std::string::npos ||
           lower.find("bg-f32") != std::string::npos;
}

// ============================================================================
// Contract-Based Adapter
// Uses training contract directly (no detection needed)
// ============================================================================
class ContractBasedAdapter {
public:
    explicit ContractBasedAdapter(const TrainingContract& contract) 
        : contract_(contract) {}
    
    // Format prompt according to contract
    std::string FormatPrompt(std::string_view user_prompt, 
                             std::string_view system_prompt = "") const {
        // Internal models: ignore system prompt if not supported
        if (!contract_.uses_system_prompt) {
            system_prompt = "";
        }
        
        std::string result;
        
        // Add BOS token
        if (!contract_.bos_token.empty()) {
            result += contract_.bos_token;
        }
        
        // Add system prompt if supported
        if (!system_prompt.empty()) {
            result += system_prompt;
            result += "\n\n";
        }
        
        // Add user prompt
        result += user_prompt;
        
        return result;
    }
    
    // Parse output according to contract
    std::string ParseOutput(std::string_view raw_output) const {
        std::string result;
        
        // Strip thinking prefix if present
        if (!contract_.thinking_prefix.empty()) {
            if (raw_output.size() >= contract_.thinking_prefix.size() &&
                raw_output.substr(0, contract_.thinking_prefix.size()) == contract_.thinking_prefix) {
                raw_output = raw_output.substr(contract_.thinking_prefix.size());
            }
        }
        
        // Extract content between markers
        if (!contract_.output_start_marker.empty() && !contract_.output_end_marker.empty()) {
            size_t start = raw_output.find(contract_.output_start_marker);
            if (start != std::string_view::npos) {
                start += contract_.output_start_marker.size();
                
                // Try primary end marker
                size_t end = raw_output.find(contract_.output_end_marker, start);
                
                // Try alternate end marker (e.g., [/TEXT] vs [END])
                if (end == std::string_view::npos && contract_.output_end_marker == "[END]") {
                    end = raw_output.find("[/TEXT]", start);
                }
                
                if (end != std::string_view::npos) {
                    result = std::string(raw_output.substr(start, end - start));
                    // Trim whitespace
                    size_t first = result.find_first_not_of(" \t\n\r");
                    if (first != std::string::npos) {
                        size_t last = result.find_last_not_of(" \t\n\r");
                        result = result.substr(first, last - first + 1);
                    }
                    return result;
                }
            }
        }
        
        // Fallback: return raw output
        return std::string(raw_output);
    }
    
    // Get stop sequences
    std::vector<std::string> GetStopSequences() const {
        std::vector<std::string> result;
        for (auto seq : contract_.stop_sequences) {
            result.emplace_back(seq);
        }
        return result;
    }
    
    // Check if supports system prompt
    bool SupportsSystemPrompt() const { return contract_.uses_system_prompt; }
    
    // Get contract info
    std::string_view GetFamilyName() const { return contract_.family_name; }
    std::string_view GetVersion() const { return contract_.version; }

private:
    const TrainingContract& contract_;
};

// ============================================================================
// Unified Model Resolution
// First checks training contract, then falls back to detection
// ============================================================================
class UnifiedModelResolver {
public:
    // Resolve a model - returns adapter if internal, null if external
    static std::unique_ptr<ContractBasedAdapter> ResolveInternal(std::string_view model_name);
    
    // Check if model should use training contract
    static bool ShouldUseContract(std::string_view model_name);
};

inline std::unique_ptr<ContractBasedAdapter> 
UnifiedModelResolver::ResolveInternal(std::string_view model_name) {
    const auto* contract = TrainingContractRegistry::GetContract(model_name);
    if (contract) {
        return std::make_unique<ContractBasedAdapter>(*contract);
    }
    return nullptr;
}

inline bool UnifiedModelResolver::ShouldUseContract(std::string_view model_name) {
    return TrainingContractRegistry::IsInternalModel(model_name);
}

} // namespace RawrXD

#endif // RAWRXD_TRAINING_CONTRACT_HPP
