#pragma once
#ifndef RAWRXD_MODEL_ADAPTER_HPP
#define RAWRXD_MODEL_ADAPTER_HPP

#include <string>
#include <functional>

namespace RawrXD {

// ============================================================================
// Model Adapter Interface
// Unified interface for model-specific prompt formatting and output parsing
// ============================================================================
class IModelAdapter {
public:
    virtual ~IModelAdapter() = default;
    
    // Get adapter name
    virtual const char* Name() const = 0;
    
    // Format prompt for this model type
    virtual std::string FormatPrompt(const std::string& prompt, const std::string& systemPrompt = "") const = 0;
    
    // Parse model output (strip custom markers, etc.)
    virtual std::string ParseOutput(const std::string& output) const = 0;
    
    // Check if this adapter matches the model name
    virtual bool Matches(const std::string& modelName) const = 0;
};

// ============================================================================
// Generic Adapter - Pass-through for standard models
// ============================================================================
class GenericAdapter : public IModelAdapter {
public:
    const char* Name() const override { return "generic"; }
    
    std::string FormatPrompt(const std::string& prompt, const std::string& systemPrompt) const override {
        (void)systemPrompt;
        return prompt;
    }
    
    std::string ParseOutput(const std::string& output) const override {
        return output;
    }
    
    bool Matches(const std::string& modelName) const override {
        (void)modelName;
        return true; // Fallback matches everything
    }
};

// ============================================================================
// Mistral/LLaMA-2 Adapter - [INST] ... [/INST] format
// ============================================================================
class MistralLlama2Adapter : public IModelAdapter {
public:
    const char* Name() const override { return "mistral_llama2"; }
    
    std::string FormatPrompt(const std::string& prompt, const std::string& systemPrompt) const override {
        if (!systemPrompt.empty()) {
            return "[INST] <<SYS>>\n" + systemPrompt + "\n<</SYS>>\n\n" + prompt + " [/INST]";
        }
        return "[INST] " + prompt + " [/INST]";
    }
    
    std::string ParseOutput(const std::string& output) const override {
        // Strip any [TEXT]...[END] or similar custom markers
        return ParseCustomMarkers(output);
    }
    
    bool Matches(const std::string& modelName) const override {
        std::string lower = modelName;
        for (char& c : lower) {
            if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        }
        return lower.find("mistral") != std::string::npos ||
               lower.find("llama2") != std::string::npos ||
               lower.find("llama-2") != std::string::npos ||
               lower.find("dolphin") != std::string::npos ||
               lower.find("openhermes") != std::string::npos ||
               lower.find("neural") != std::string::npos ||
               lower.find("bigdaddyg") != std::string::npos;
    }

private:
    static std::string ParseCustomMarkers(const std::string& raw) {
        // Check for [TEXT]...[END] format
        size_t textStart = raw.find("[TEXT]");
        if (textStart != std::string::npos) {
            textStart += 6;
            size_t endPos = raw.find("[END]", textStart);
            if (endPos != std::string::npos) {
                std::string extracted = raw.substr(textStart, endPos - textStart);
                size_t first = extracted.find_first_not_of(" \t\n\r");
                if (first != std::string::npos) {
                    size_t last = extracted.find_last_not_of(" \t\n\r");
                    return extracted.substr(first, last - first + 1);
                }
                return extracted;
            }
        }
        
        // Check for [/TEXT] variant
        textStart = raw.find("[TEXT]");
        if (textStart != std::string::npos) {
            textStart += 6;
            size_t endPos = raw.find("[/TEXT]", textStart);
            if (endPos != std::string::npos) {
                std::string extracted = raw.substr(textStart, endPos - textStart);
                size_t first = extracted.find_first_not_of(" \t\n\r");
                if (first != std::string::npos) {
                    size_t last = extracted.find_last_not_of(" \t\n\r");
                    return extracted.substr(first, last - first + 1);
                }
                return extracted;
            }
        }
        
        // Strip leading "..." thinking tokens
        if (raw.find_first_not_of(" \t\n\r") == 0 && raw.substr(0, 3) == "...") {
            size_t contentStart = raw.find_first_not_of(".", 3);
            if (contentStart != std::string::npos) {
                return raw.substr(contentStart);
            }
        }
        
        return raw;
    }
};

// ============================================================================
// Phi-3 Adapter - <|user|>...<|assistant|> format
// ============================================================================
class Phi3Adapter : public IModelAdapter {
public:
    const char* Name() const override { return "phi3"; }
    
    std::string FormatPrompt(const std::string& prompt, const std::string& systemPrompt) const override {
        if (!systemPrompt.empty()) {
            return "<|system|>\n" + systemPrompt + "<|end|>\n<|user|>\n" + prompt + "<|end|>\n<|assistant|>\n";
        }
        return "<|user|>\n" + prompt + "<|end|>\n<|assistant|>\n";
    }
    
    std::string ParseOutput(const std::string& output) const override {
        return output; // Phi-3 outputs clean text
    }
    
    bool Matches(const std::string& modelName) const override {
        std::string lower = modelName;
        for (char& c : lower) {
            if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        }
        return lower.find("phi3") != std::string::npos ||
               lower.find("phi-3") != std::string::npos;
    }
};

// ============================================================================
// LLaMA-3 Adapter - <|begin_of_text|>... format
// ============================================================================
class Llama3Adapter : public IModelAdapter {
public:
    const char* Name() const override { return "llama3"; }
    
    std::string FormatPrompt(const std::string& prompt, const std::string& systemPrompt) const override {
        if (!systemPrompt.empty()) {
            return "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" + 
                   systemPrompt + "<|eot_id|>" +
                   "<|start_header_id|>user<|end_header_id|>\n\n" + prompt + "<|eot_id|>" +
                   "<|start_header_id|>assistant<|end_header_id|>\n\n";
        }
        return "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n" + prompt + 
               "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n";
    }
    
    std::string ParseOutput(const std::string& output) const override {
        return output; // LLaMA-3 outputs clean text
    }
    
    bool Matches(const std::string& modelName) const override {
        std::string lower = modelName;
        for (char& c : lower) {
            if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        }
        return lower.find("llama3") != std::string::npos ||
               lower.find("llama-3") != std::string::npos;
    }
};

// ============================================================================
// Model Adapter Registry
// Factory for getting the right adapter for each model
// ============================================================================
class ModelAdapterRegistry {
public:
    static ModelAdapterRegistry& Instance() {
        static ModelAdapterRegistry instance;
        return instance;
    }
    
    // Get adapter for a model name
    const IModelAdapter* GetAdapter(const std::string& modelName) const {
        // Check registered adapters in order
        for (const auto& adapter : adapters_) {
            if (adapter->Matches(modelName)) {
                return adapter.get();
            }
        }
        return generic_.get();
    }
    
    // Register a custom adapter
    void Register(std::unique_ptr<IModelAdapter> adapter) {
        adapters_.push_back(std::move(adapter));
    }
    
private:
    ModelAdapterRegistry() {
        // Register built-in adapters (order matters - more specific first)
        adapters_.push_back(std::make_unique<Phi3Adapter>());
        adapters_.push_back(std::make_unique<Llama3Adapter>());
        adapters_.push_back(std::make_unique<MistralLlama2Adapter>());
        
        // Generic fallback
        generic_ = std::make_unique<GenericAdapter>();
    }
    
    std::vector<std::unique_ptr<IModelAdapter>> adapters_;
    std::unique_ptr<IModelAdapter> generic_;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Get the appropriate adapter for a model
inline const IModelAdapter* GetModelAdapter(const std::string& modelName) {
    return ModelAdapterRegistry::Instance().GetAdapter(modelName);
}

// Format a prompt for a specific model
inline std::string FormatModelPrompt(const std::string& modelName, 
                                      const std::string& prompt, 
                                      const std::string& systemPrompt = "") {
    auto* adapter = GetModelAdapter(modelName);
    return adapter ? adapter->FormatPrompt(prompt, systemPrompt) : prompt;
}

// Parse output from a specific model
inline std::string ParseModelOutput(const std::string& modelName, const std::string& output) {
    auto* adapter = GetModelAdapter(modelName);
    return adapter ? adapter->ParseOutput(output) : output;
}

} // namespace RawrXD

#endif // RAWRXD_MODEL_ADAPTER_HPP
