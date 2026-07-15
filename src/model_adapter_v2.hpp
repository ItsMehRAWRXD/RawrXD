#pragma once
#ifndef RAWRXD_MODEL_ADAPTER_V2_HPP
#define RAWRXD_MODEL_ADAPTER_V2_HPP

#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <cctype>

namespace RawrXD {

// ============================================================================
// Model Family Detection
// Centralized model identification - handles aliases and versions
// ============================================================================
enum class ModelFamily {
    Generic,        // Default fallback
    Phi3,           // Phi-3 models
    Llama3,         // Llama-3 models
    Llama2,         // Llama-2 models
    Mistral,        // Mistral models
    BigDaddyG,      // Custom BigDaddyG models
    Qwen,           // Qwen models
    Gemma,          // Gemma models
    Codestral       // Codestral models
};

// Convert string to lowercase for comparison
inline std::string ToLower(std::string_view sv) {
    std::string result;
    result.reserve(sv.length());
    for (char c : sv) {
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return result;
}

// Detect model family from name (handles aliases like "bigdaddyg:latest" vs "bigdaddyg:v2")
inline ModelFamily DetectModelFamily(std::string_view name) {
    std::string lower = ToLower(name);
    
    // Check in order of specificity (most specific first)
    if (lower.find("bigdaddyg") != std::string::npos) return ModelFamily::BigDaddyG;
    if (lower.find("phi3") != std::string::npos || lower.find("phi-3") != std::string::npos) return ModelFamily::Phi3;
    if (lower.find("llama3") != std::string::npos || lower.find("llama-3") != std::string::npos) return ModelFamily::Llama3;
    if (lower.find("llama2") != std::string::npos || lower.find("llama-2") != std::string::npos) return ModelFamily::Llama2;
    if (lower.find("mistral") != std::string::npos) return ModelFamily::Mistral;
    if (lower.find("qwen") != std::string::npos) return ModelFamily::Qwen;
    if (lower.find("gemma") != std::string::npos) return ModelFamily::Gemma;
    if (lower.find("codestral") != std::string::npos) return ModelFamily::Codestral;
    
    return ModelFamily::Generic;
}

// ============================================================================
// Prompt Formatter Interface
// ============================================================================
struct IPromptFormatter {
    virtual ~IPromptFormatter() = default;
    virtual std::string Format(std::string_view system, std::string_view prompt) const = 0;
};

// ============================================================================
// Output Parser Interface (stateless)
// ============================================================================
struct IOutputParser {
    virtual ~IOutputParser() = default;
    virtual std::string Parse(std::string_view output) const = 0;
};

// ============================================================================
// Streaming Output Parser Interface (stateful)
// ============================================================================
class IStreamingOutputParser {
public:
    virtual ~IStreamingOutputParser() = default;
    
    // Feed a chunk of output
    virtual void Feed(std::string_view chunk) = 0;
    
    // Check if there's clean output available
    virtual bool HasOutput() const = 0;
    
    // Consume available clean output
    virtual std::string Consume() = 0;
    
    // Signal end of stream
    virtual void Finish() = 0;
    
    // Reset for reuse
    virtual void Reset() = 0;
};

// ============================================================================
// Concrete Prompt Formatters
// ============================================================================

// Generic - no formatting
struct GenericFormatter : public IPromptFormatter {
    std::string Format(std::string_view system, std::string_view prompt) const override {
        (void)system;
        return std::string(prompt);
    }
};

// Mistral/LLaMA-2 - [INST] format
struct MistralLlama2Formatter : public IPromptFormatter {
    std::string Format(std::string_view system, std::string_view prompt) const override {
        if (!system.empty()) {
            return "[INST] <<SYS>>\n" + std::string(system) + "\n<</SYS>>\n\n" + std::string(prompt) + " [/INST]";
        }
        return "[INST] " + std::string(prompt) + " [/INST]";
    }
};

// Phi-3 - <|user|> format
struct Phi3Formatter : public IPromptFormatter {
    std::string Format(std::string_view system, std::string_view prompt) const override {
        if (!system.empty()) {
            return "<|system|>\n" + std::string(system) + "<|end|>\n<|user|>\n" + std::string(prompt) + "<|end|>\n<|assistant|>\n";
        }
        return "<|user|>\n" + std::string(prompt) + "<|end|>\n<|assistant|>\n";
    }
};

// LLaMA-3 - <|begin_of_text|> format
struct Llama3Formatter : public IPromptFormatter {
    std::string Format(std::string_view system, std::string_view prompt) const override {
        if (!system.empty()) {
            return "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" + 
                   std::string(system) + "<|eot_id|>" +
                   "<|start_header_id|>user<|end_header_id|>\n\n" + std::string(prompt) + "<|eot_id|>" +
                   "<|start_header_id|>assistant<|end_header_id|>\n\n";
        }
        return "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n" + std::string(prompt) + 
               "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n";
    }
};

// ============================================================================
// Concrete Output Parsers
// ============================================================================

// Generic - pass-through
struct GenericParser : public IOutputParser {
    std::string Parse(std::string_view output) const override {
        return std::string(output);
    }
};

// BigDaddyG - handles [TEXT]...[END] markers
struct BigDaddyGParser : public IOutputParser {
    std::string Parse(std::string_view output) const override {
        // Check for [TEXT]...[END] format
        size_t textStart = output.find("[TEXT]");
        if (textStart != std::string_view::npos) {
            textStart += 6;
            size_t endPos = output.find("[END]", textStart);
            if (endPos != std::string_view::npos) {
                std::string_view extracted = output.substr(textStart, endPos - textStart);
                // Trim whitespace
                size_t first = extracted.find_first_not_of(" \t\n\r");
                if (first != std::string_view::npos) {
                    size_t last = extracted.find_last_not_of(" \t\n\r");
                    return std::string(extracted.substr(first, last - first + 1));
                }
                return std::string(extracted);
            }
        }
        
        // Check for [/TEXT] variant
        textStart = output.find("[TEXT]");
        if (textStart != std::string_view::npos) {
            textStart += 6;
            size_t endPos = output.find("[/TEXT]", textStart);
            if (endPos != std::string_view::npos) {
                std::string_view extracted = output.substr(textStart, endPos - textStart);
                size_t first = extracted.find_first_not_of(" \t\n\r");
                if (first != std::string_view::npos) {
                    size_t last = extracted.find_last_not_of(" \t\n\r");
                    return std::string(extracted.substr(first, last - first + 1));
                }
                return std::string(extracted);
            }
        }
        
        // Strip leading "..." thinking tokens
        if (output.size() >= 3 && output.substr(0, 3) == "...") {
            size_t contentStart = output.find_first_not_of(".", 3);
            if (contentStart != std::string_view::npos) {
                return std::string(output.substr(contentStart));
            }
        }
        
        return std::string(output);
    }
};

// ============================================================================
// Streaming Parser for BigDaddyG
// Handles markers split across chunks
// ============================================================================
class BigDaddyGStreamingParser : public IStreamingOutputParser {
public:
    void Feed(std::string_view chunk) override {
        buffer_ += std::string(chunk);
        ProcessBuffer();
    }
    
    bool HasOutput() const override {
        return !outputQueue_.empty();
    }
    
    std::string Consume() override {
        if (outputQueue_.empty()) return "";
        std::string result = outputQueue_;
        outputQueue_.clear();
        return result;
    }
    
    void Finish() override {
        // Flush any remaining content
        if (!buffer_.empty()) {
            // If we have content after [TEXT] but no [END], output it anyway
            size_t textPos = buffer_.find("[TEXT]");
            if (textPos != std::string::npos) {
                textPos += 6;
                std::string_view remaining = std::string_view(buffer_).substr(textPos);
                size_t first = remaining.find_first_not_of(" \t\n\r");
                if (first != std::string_view::npos) {
                    outputQueue_ += std::string(remaining.substr(first));
                }
            } else {
                // No markers found, output raw
                outputQueue_ += buffer_;
            }
            buffer_.clear();
        }
    }
    
    void Reset() override {
        buffer_.clear();
        outputQueue_.clear();
        inTextBlock_ = false;
    }

private:
    std::string buffer_;
    std::string outputQueue_;
    bool inTextBlock_ = false;
    
    void ProcessBuffer() {
        // Look for complete [TEXT]...[END] blocks
        while (true) {
            if (!inTextBlock_) {
                // Looking for [TEXT]
                size_t textPos = buffer_.find("[TEXT]");
                if (textPos == std::string::npos) break;
                
                inTextBlock_ = true;
                buffer_ = buffer_.substr(textPos + 6);
            } else {
                // Looking for [END] or [/TEXT]
                size_t endPos = buffer_.find("[END]");
                size_t closePos = buffer_.find("[/TEXT]");
                
                size_t markerPos = std::min(
                    endPos == std::string::npos ? buffer_.size() : endPos,
                    closePos == std::string::npos ? buffer_.size() : closePos
                );
                
                if (markerPos == buffer_.size()) {
                    // No end marker yet - check if we have content to output
                    if (buffer_.size() > 10) { // Arbitrary threshold
                        size_t first = buffer_.find_first_not_of(" \t\n\r");
                        if (first != std::string::npos) {
                            outputQueue_ += buffer_.substr(first);
                            buffer_.clear();
                        }
                    }
                    break;
                }
                
                // Found end marker
                std::string_view content(buffer_.data(), markerPos);
                size_t first = content.find_first_not_of(" \t\n\r");
                if (first != std::string_view::npos) {
                    size_t last = content.find_last_not_of(" \t\n\r");
                    outputQueue_ += std::string(content.substr(first, last - first + 1));
                }
                
                inTextBlock_ = false;
                buffer_ = buffer_.substr(markerPos + (endPos == markerPos ? 5 : 7));
            }
        }
    }
};

// ============================================================================
// Model Adapter Factory
// Returns appropriate formatter/parser for a model family
// ============================================================================
class ModelAdapterFactory {
public:
    static const IPromptFormatter* GetFormatter(ModelFamily family) {
        static GenericFormatter generic;
        static MistralLlama2Formatter mistral;
        static Phi3Formatter phi3;
        static Llama3Formatter llama3;
        
        switch (family) {
            case ModelFamily::Phi3: return &phi3;
            case ModelFamily::Llama3: return &llama3;
            case ModelFamily::Llama2:
            case ModelFamily::Mistral:
            case ModelFamily::BigDaddyG:
                return &mistral;
            default:
                return &generic;
        }
    }
    
    static const IOutputParser* GetParser(ModelFamily family) {
        static GenericParser generic;
        static BigDaddyGParser bigdaddyg;
        
        switch (family) {
            case ModelFamily::BigDaddyG:
                return &bigdaddyg;
            default:
                return &generic;
        }
    }
    
    static std::unique_ptr<IStreamingOutputParser> CreateStreamingParser(ModelFamily family) {
        switch (family) {
            case ModelFamily::BigDaddyG:
                return std::make_unique<BigDaddyGStreamingParser>();
            default:
                // Generic streaming parser (just accumulates)
                return std::make_unique<BigDaddyGStreamingParser>(); // TODO: Create GenericStreamingParser
        }
    }
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Format a prompt for a specific model
inline std::string FormatModelPrompt(std::string_view modelName, 
                                      std::string_view prompt, 
                                      std::string_view systemPrompt = "") {
    ModelFamily family = DetectModelFamily(modelName);
    const auto* formatter = ModelAdapterFactory::GetFormatter(family);
    return formatter ? formatter->Format(systemPrompt, prompt) : std::string(prompt);
}

// Parse output from a specific model
inline std::string ParseModelOutput(std::string_view modelName, std::string_view output) {
    ModelFamily family = DetectModelFamily(modelName);
    const auto* parser = ModelAdapterFactory::GetParser(family);
    return parser ? parser->Parse(output) : std::string(output);
}

// Create streaming parser for a model
inline std::unique_ptr<IStreamingOutputParser> CreateStreamingParser(std::string_view modelName) {
    ModelFamily family = DetectModelFamily(modelName);
    return ModelAdapterFactory::CreateStreamingParser(family);
}

} // namespace RawrXD

#endif // RAWRXD_MODEL_ADAPTER_V2_HPP
