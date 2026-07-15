#pragma once
#ifndef RAWRXD_MODEL_REGISTRY_HPP
#define RAWRXD_MODEL_REGISTRY_HPP

#include "gguf_metadata_reader.hpp"
#include <string_view>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

namespace RawrXD {

// ============================================================================
// Prompt Template Types
// ============================================================================
enum class PromptTemplate {
    RAW_BOS,        // <s> + raw prompt (BigDaddyG style)
    MISTRAL_LLAMA2, // [INST] ... [/INST]
    PHI3,           // <|user|> ... <|assistant|>
    LLAMA3,         // <|begin_of_text|> ... <|eot_id|>
    CHATML,         // <|im_start|> ... <|im_end|>
    GEMMA,          // Gemma format
    DEEPSEEK,       // DeepSeek format
    GENERIC         // Pass-through
};

// ============================================================================
// Output Parser Types
// ============================================================================
enum class OutputParser {
    PLAIN,          // No parsing needed
    TEXT_MARKERS,   // [TEXT]...[END] (BigDaddyG)
    THINKING,       // Strip <think>...</think> (DeepSeek R1)
    CODE_BLOCKS     // Extract ```code``` blocks
};

// ============================================================================
// Model Descriptor
// Unified description of a model's requirements
// ============================================================================
struct ModelDescriptor {
    PromptTemplate prompt_template = PromptTemplate::GENERIC;
    OutputParser output_parser = OutputParser::PLAIN;
    bool supports_system_prompt = true;
    bool supports_streaming = true;
    std::string chat_template;      // Raw template from GGUF if available
    std::string architecture;       // llama, qwen, gemma, etc.
    
    // Check if this descriptor was loaded from GGUF metadata
    bool from_gguf = false;
};

// ============================================================================
// Model Registry
// Central registry for model configurations
// ============================================================================
class ModelRegistry {
public:
    static ModelRegistry& Instance();
    
    // Lookup model descriptor (tries GGUF first, then family fallback)
    ModelDescriptor Lookup(const std::string& model_name_or_path) const;
    
    // Force reload from GGUF file
    ModelDescriptor LookupFromGGUF(const std::string& gguf_path) const;
    
    // Register custom descriptor for a model pattern
    void Register(const std::string& pattern, const ModelDescriptor& descriptor);
    
    // Clear cache (useful for testing)
    void ClearCache();

private:
    ModelRegistry() = default;
    
    mutable std::unordered_map<std::string, ModelDescriptor> cache_;
    std::vector<std::pair<std::string, ModelDescriptor>> custom_registrations_;
    
    // Detection methods
    ModelDescriptor DetectFromGGUF(const std::string& path) const;
    ModelDescriptor DetectFromFamily(const std::string& name) const;
    ModelDescriptor DetectFromOllama(const std::string& name) const;
    
    // Pattern matching
    bool MatchesPattern(const std::string& name, const std::string& pattern) const;
};

// ============================================================================
// Prompt Formatter
// ============================================================================
class PromptFormatter {
public:
    static std::string Format(const ModelDescriptor& desc,
                               std::string_view system_prompt,
                               std::string_view user_prompt);
    
    static std::string Format(PromptTemplate type,
                               std::string_view system_prompt,
                               std::string_view user_prompt);
};

// ============================================================================
// Output Parser (Stateless)
// ============================================================================
class OutputParserUtil {
public:
    static std::string Parse(const ModelDescriptor& desc, std::string_view output);
    static std::string Parse(OutputParser type, std::string_view output);
};

// ============================================================================
// Streaming Output Parser (Stateful)
// ============================================================================
class IStreamingParser {
public:
    virtual ~IStreamingParser() = default;
    virtual void Feed(std::string_view chunk) = 0;
    virtual bool HasOutput() const = 0;
    virtual std::string Consume() = 0;
    virtual void Finish() = 0;
    virtual void Reset() = 0;
};

// Factory for creating streaming parsers
std::unique_ptr<IStreamingParser> CreateStreamingParser(const ModelDescriptor& desc);

// ============================================================================
// Convenience Functions
// ============================================================================
inline std::string FormatModelPrompt(const std::string& model_name,
                                      std::string_view system_prompt,
                                      std::string_view user_prompt) {
    auto desc = ModelRegistry::Instance().Lookup(model_name);
    return PromptFormatter::Format(desc, system_prompt, user_prompt);
}

inline std::string ParseModelOutput(const std::string& model_name,
                                     std::string_view output) {
    auto desc = ModelRegistry::Instance().Lookup(model_name);
    return OutputParserUtil::Parse(desc, output);
}

// ============================================================================
// Implementation
// ============================================================================

inline ModelRegistry& ModelRegistry::Instance() {
    static ModelRegistry instance;
    return instance;
}

inline void ModelRegistry::ClearCache() {
    cache_.clear();
}

inline void ModelRegistry::Register(const std::string& pattern, const ModelDescriptor& descriptor) {
    custom_registrations_.emplace_back(pattern, descriptor);
}

inline bool ModelRegistry::MatchesPattern(const std::string& name, const std::string& pattern) const {
    // Simple substring matching for now
    // Could be extended to regex or glob patterns
    std::string lower_name = name;
    std::string lower_pattern = pattern;
    for (auto& c : lower_name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (auto& c : lower_pattern) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return lower_name.find(lower_pattern) != std::string::npos;
}

inline ModelDescriptor ModelRegistry::Lookup(const std::string& model_name_or_path) const {
    // Check cache first
    auto it = cache_.find(model_name_or_path);
    if (it != cache_.end()) {
        return it->second;
    }
    
    // Check custom registrations
    for (const auto& [pattern, desc] : custom_registrations_) {
        if (MatchesPattern(model_name_or_path, pattern)) {
            cache_[model_name_or_path] = desc;
            return desc;
        }
    }
    
    // Try to detect from GGUF if it's a file path
    if (model_name_or_path.find(".gguf") != std::string::npos ||
        model_name_or_path.find(":\\") != std::string::npos ||
        model_name_or_path.find("/") != std::string::npos) {
        auto desc = DetectFromGGUF(model_name_or_path);
        if (desc.from_gguf) {
            cache_[model_name_or_path] = desc;
            return desc;
        }
    }
    
    // Try Ollama model name patterns
    auto desc = DetectFromOllama(model_name_or_path);
    cache_[model_name_or_path] = desc;
    return desc;
}

inline ModelDescriptor ModelRegistry::LookupFromGGUF(const std::string& gguf_path) const {
    return DetectFromGGUF(gguf_path);
}

inline ModelDescriptor ModelRegistry::DetectFromGGUF(const std::string& path) const {
    ModelDescriptor desc;
    
    GGUFMetadata metadata;
    if (!GGUFMetadataReader::Read(path, metadata)) {
        return desc; // Return default descriptor
    }
    
    desc.from_gguf = true;
    desc.architecture = metadata.GetArchitecture();
    desc.chat_template = metadata.GetChatTemplate();
    
    // Map prompt style to enum
    std::string style = metadata.GetPromptStyle();
    if (style == "raw_bos") desc.prompt_template = PromptTemplate::RAW_BOS;
    else if (style == "mistral_llama2") desc.prompt_template = PromptTemplate::MISTRAL_LLAMA2;
    else if (style == "phi3") desc.prompt_template = PromptTemplate::PHI3;
    else if (style == "llama3") desc.prompt_template = PromptTemplate::LLAMA3;
    else if (style == "chatml") desc.prompt_template = PromptTemplate::CHATML;
    else desc.prompt_template = PromptTemplate::GENERIC;
    
    // Map output parser to enum
    std::string parser = metadata.GetOutputParser();
    if (parser == "text_markers") desc.output_parser = OutputParser::TEXT_MARKERS;
    else if (parser == "thinking") desc.output_parser = OutputParser::THINKING;
    else if (parser == "code_blocks") desc.output_parser = OutputParser::CODE_BLOCKS;
    else desc.output_parser = OutputParser::PLAIN;
    
    return desc;
}

inline ModelDescriptor ModelRegistry::DetectFromOllama(const std::string& name) const {
    // Convert to lowercase for matching
    std::string lower = name;
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    
    ModelDescriptor desc;
    
    // BigDaddyG family - RAW_BOS + TEXT_MARKERS
    if (lower.find("bigdaddyg") != std::string::npos ||
        lower.find("bigdaddy") != std::string::npos ||
        lower.find("bg-") != std::string::npos ||
        lower.find("bg40") != std::string::npos ||
        lower.find("cheetah") != std::string::npos) {
        desc.prompt_template = PromptTemplate::RAW_BOS;
        desc.output_parser = OutputParser::TEXT_MARKERS;
        desc.supports_system_prompt = false;
        desc.architecture = "llama";
        return desc;
    }
    
    // Phi-3 family
    if (lower.find("phi3") != std::string::npos ||
        lower.find("phi-3") != std::string::npos) {
        desc.prompt_template = PromptTemplate::PHI3;
        desc.output_parser = OutputParser::PLAIN;
        desc.architecture = "phi3";
        return desc;
    }
    
    // LLaMA-3 family
    if (lower.find("llama3") != std::string::npos ||
        lower.find("llama-3") != std::string::npos) {
        desc.prompt_template = PromptTemplate::LLAMA3;
        desc.output_parser = OutputParser::PLAIN;
        desc.architecture = "llama";
        return desc;
    }
    
    // LLaMA-2 / Mistral family
    if (lower.find("llama2") != std::string::npos ||
        lower.find("llama-2") != std::string::npos ||
        lower.find("mistral") != std::string::npos ||
        lower.find("dolphin") != std::string::npos ||
        lower.find("codellama") != std::string::npos) {
        desc.prompt_template = PromptTemplate::MISTRAL_LLAMA2;
        desc.output_parser = OutputParser::PLAIN;
        desc.architecture = "llama";
        return desc;
    }
    
    // Qwen family
    if (lower.find("qwen") != std::string::npos) {
        desc.prompt_template = PromptTemplate::CHATML;
        desc.output_parser = OutputParser::PLAIN;
        desc.architecture = "qwen";
        return desc;
    }
    
    // Gemma family
    if (lower.find("gemma") != std::string::npos) {
        desc.prompt_template = PromptTemplate::GEMMA;
        desc.output_parser = OutputParser::PLAIN;
        desc.architecture = "gemma";
        return desc;
    }
    
    // DeepSeek family
    if (lower.find("deepseek") != std::string::npos) {
        desc.prompt_template = PromptTemplate::CHATML;
        desc.output_parser = OutputParser::THINKING;
        desc.architecture = "deepseek";
        return desc;
    }
    
    // Codestral
    if (lower.find("codestral") != std::string::npos) {
        desc.prompt_template = PromptTemplate::MISTRAL_LLAMA2;
        desc.output_parser = OutputParser::CODE_BLOCKS;
        desc.architecture = "mistral";
        return desc;
    }
    
    // Default
    desc.prompt_template = PromptTemplate::GENERIC;
    desc.output_parser = OutputParser::PLAIN;
    return desc;
}

// ============================================================================
// Prompt Formatter Implementation
// ============================================================================
inline std::string PromptFormatter::Format(const ModelDescriptor& desc,
                                            std::string_view system_prompt,
                                            std::string_view user_prompt) {
    // If we have a raw chat template from GGUF, use it
    if (!desc.chat_template.empty() && desc.from_gguf) {
        // Simple template substitution
        std::string result = desc.chat_template;
        
        // Replace {{system}} or <<SYS>>...<</SYS>>
        if (!system_prompt.empty()) {
            size_t pos = result.find("{{system}}");
            if (pos != std::string::npos) {
                result.replace(pos, 10, system_prompt);
            }
            pos = result.find("<<SYS>>");
            if (pos != std::string::npos) {
                size_t end_pos = result.find("<</SYS>>", pos);
                if (end_pos != std::string::npos) {
                    result.replace(pos, end_pos - pos + 8, system_prompt);
                }
            }
        }
        
        // Replace {{prompt}} or {{user}}
        size_t pos = result.find("{{prompt}}");
        if (pos != std::string::npos) {
            result.replace(pos, 10, user_prompt);
        }
        pos = result.find("{{user}}");
        if (pos != std::string::npos) {
            result.replace(pos, 8, user_prompt);
        }
        
        return result;
    }
    
    // Otherwise use enum-based formatting
    return Format(desc.prompt_template, system_prompt, user_prompt);
}

inline std::string PromptFormatter::Format(PromptTemplate type,
                                            std::string_view system_prompt,
                                            std::string_view user_prompt) {
    switch (type) {
        case PromptTemplate::RAW_BOS:
            // <s> + raw prompt (no system prompt support)
            return "<s>" + std::string(user_prompt);
            
        case PromptTemplate::MISTRAL_LLAMA2: {
            // [INST] <<SYS>>...system...<</SYS>> prompt [/INST]
            if (!system_prompt.empty()) {
                return "[INST] <<SYS>>\n" + std::string(system_prompt) + 
                       "\n<</SYS>>\n\n" + std::string(user_prompt) + " [/INST]";
            }
            return "[INST] " + std::string(user_prompt) + " [/INST]";
        }
            
        case PromptTemplate::PHI3: {
            // <|system|>...<|end|><|user|>...<|end|><|assistant|>
            if (!system_prompt.empty()) {
                return "<|system|>\n" + std::string(system_prompt) + 
                       "<|end|>\n<|user|>\n" + std::string(user_prompt) + 
                       "<|end|>\n<|assistant|>\n";
            }
            return "<|user|>\n" + std::string(user_prompt) + 
                   "<|end|>\n<|assistant|>\n";
        }
            
        case PromptTemplate::LLAMA3: {
            // <|begin_of_text|><|start_header_id|>system<|end_header_id|>...
            if (!system_prompt.empty()) {
                return "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" +
                       std::string(system_prompt) + "<|eot_id|>" +
                       "<|start_header_id|>user<|end_header_id|>\n\n" +
                       std::string(user_prompt) + "<|eot_id|>" +
                       "<|start_header_id|>assistant<|end_header_id|>\n\n";
            }
            return "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n" +
                   std::string(user_prompt) + "<|eot_id|>" +
                   "<|start_header_id|>assistant<|end_header_id|>\n\n";
        }
            
        case PromptTemplate::CHATML: {
            // <|im_start|>system<|im_end|>...
            if (!system_prompt.empty()) {
                return "<|im_start|>system\n" + std::string(system_prompt) + 
                       "<|im_end|>\n<|im_start|>user\n" + std::string(user_prompt) + 
                       "<|im_end|>\n<|im_start|>assistant\n";
            }
            return "<|im_start|>user\n" + std::string(user_prompt) + 
                   "<|im_end|>\n<|im_start|>assistant\n";
        }
            
        case PromptTemplate::GEMMA: {
            // <start_of_turn>user...prompt...<end_of_turn>
            if (!system_prompt.empty()) {
                return "<start_of_turn>user\n" + std::string(system_prompt) + 
                       "\n\n" + std::string(user_prompt) + "<end_of_turn>\n" +
                       "<start_of_turn>model\n";
            }
            return "<start_of_turn>user\n" + std::string(user_prompt) + 
                   "<end_of_turn>\n<start_of_turn>model\n";
        }
            
        case PromptTemplate::GENERIC:
        default:
            if (!system_prompt.empty()) {
                return "System: " + std::string(system_prompt) + "\n\nUser: " + std::string(user_prompt) + "\nAssistant: ";
            }
            return std::string(user_prompt);
    }
}

// ============================================================================
// Output Parser Implementation
// ============================================================================
inline std::string OutputParserUtil::Parse(const ModelDescriptor& desc,
                                            std::string_view output) {
    return Parse(desc.output_parser, output);
}

inline std::string OutputParserUtil::Parse(OutputParser type, std::string_view output) {
    switch (type) {
        case OutputParser::TEXT_MARKERS: {
            // Parse [TEXT]...[END] or [TEXT]...[/TEXT]
            size_t text_start = output.find("[TEXT]");
            if (text_start != std::string_view::npos) {
                text_start += 6;
                size_t end_pos = output.find("[END]", text_start);
                if (end_pos == std::string_view::npos) {
                    end_pos = output.find("[/TEXT]", text_start);
                }
                if (end_pos != std::string_view::npos) {
                    std::string_view extracted = output.substr(text_start, end_pos - text_start);
                    // Trim whitespace
                    size_t first = extracted.find_first_not_of(" \t\n\r");
                    if (first != std::string_view::npos) {
                        size_t last = extracted.find_last_not_of(" \t\n\r");
                        return std::string(extracted.substr(first, last - first + 1));
                    }
                    return std::string(extracted);
                }
            }
            // Strip leading ... thinking tokens
            if (output.size() >= 3 && output.substr(0, 3) == "...") {
                size_t content_start = output.find_first_not_of(".", 3);
                if (content_start != std::string_view::npos) {
                    return std::string(output.substr(content_start));
                }
            }
            return std::string(output);
        }
            
        case OutputParser::THINKING: {
            // Strip <think>...</think> blocks
            std::string result(output);
            size_t pos = 0;
            while ((pos = result.find("<think>", pos)) != std::string::npos) {
                size_t end_pos = result.find("</think>", pos);
                if (end_pos != std::string::npos) {
                    result.erase(pos, end_pos - pos + 9);
                } else {
                    break;
                }
            }
            return result;
        }
            
        case OutputParser::CODE_BLOCKS: {
            // Extract ```code``` blocks
            std::string result;
            size_t pos = 0;
            while ((pos = output.find("```", pos)) != std::string_view::npos) {
                pos += 3;
                // Skip language identifier
                size_t newline = output.find('\n', pos);
                if (newline != std::string_view::npos) {
                    pos = newline + 1;
                }
                size_t end_pos = output.find("```", pos);
                if (end_pos != std::string_view::npos) {
                    if (!result.empty()) result += "\n\n";
                    result += std::string(output.substr(pos, end_pos - pos));
                    pos = end_pos + 3;
                } else {
                    break;
                }
            }
            return result.empty() ? std::string(output) : result;
        }
            
        case OutputParser::PLAIN:
        default:
            return std::string(output);
    }
}

// ============================================================================
// Streaming Parser Implementations
// ============================================================================

class TextMarkersStreamingParser : public IStreamingParser {
public:
    void Feed(std::string_view chunk) override {
        buffer_ += std::string(chunk);
        ProcessBuffer();
    }
    
    bool HasOutput() const override {
        return !output_queue_.empty();
    }
    
    std::string Consume() override {
        if (output_queue_.empty()) return "";
        std::string result = output_queue_;
        output_queue_.clear();
        return result;
    }
    
    void Finish() override {
        // Flush remaining content
        if (!buffer_.empty()) {
            size_t text_pos = buffer_.find("[TEXT]");
            if (text_pos != std::string::npos) {
                text_pos += 6;
                std::string_view remaining = std::string_view(buffer_).substr(text_pos);
                size_t first = remaining.find_first_not_of(" \t\n\r");
                if (first != std::string_view::npos) {
                    output_queue_ += std::string(remaining.substr(first));
                }
            } else {
                output_queue_ += buffer_;
            }
            buffer_.clear();
        }
    }
    
    void Reset() override {
        buffer_.clear();
        output_queue_.clear();
        in_text_block_ = false;
    }

private:
    std::string buffer_;
    std::string output_queue_;
    bool in_text_block_ = false;
    
    void ProcessBuffer() {
        while (true) {
            if (!in_text_block_) {
                size_t text_pos = buffer_.find("[TEXT]");
                if (text_pos == std::string::npos) break;
                in_text_block_ = true;
                buffer_ = buffer_.substr(text_pos + 6);
            } else {
                size_t end_pos = buffer_.find("[END]");
                size_t close_pos = buffer_.find("[/TEXT]");
                
                size_t marker_pos = std::min(
                    end_pos == std::string::npos ? buffer_.size() : end_pos,
                    close_pos == std::string::npos ? buffer_.size() : close_pos
                );
                
                if (marker_pos == buffer_.size()) {
                    // No end marker yet - output what we have if enough content
                    if (buffer_.size() > 10) {
                        size_t first = buffer_.find_first_not_of(" \t\n\r");
                        if (first != std::string::npos) {
                            output_queue_ += buffer_.substr(first);
                            buffer_.clear();
                        }
                    }
                    break;
                }
                
                std::string_view content(buffer_.data(), marker_pos);
                size_t first = content.find_first_not_of(" \t\n\r");
                if (first != std::string_view::npos) {
                    size_t last = content.find_last_not_of(" \t\n\r");
                    output_queue_ += std::string(content.substr(first, last - first + 1));
                }
                
                in_text_block_ = false;
                buffer_ = buffer_.substr(marker_pos + (end_pos == marker_pos ? 5 : 7));
            }
        }
    }
};

class PlainStreamingParser : public IStreamingParser {
public:
    void Feed(std::string_view chunk) override {
        buffer_ += std::string(chunk);
    }
    
    bool HasOutput() const override {
        return !buffer_.empty();
    }
    
    std::string Consume() override {
        std::string result = buffer_;
        buffer_.clear();
        return result;
    }
    
    void Finish() override {
        // Nothing to do
    }
    
    void Reset() override {
        buffer_.clear();
    }

private:
    std::string buffer_;
};

inline std::unique_ptr<IStreamingParser> CreateStreamingParser(const ModelDescriptor& desc) {
    switch (desc.output_parser) {
        case OutputParser::TEXT_MARKERS:
            return std::make_unique<TextMarkersStreamingParser>();
        case OutputParser::PLAIN:
        case OutputParser::THINKING:
        case OutputParser::CODE_BLOCKS:
        default:
            return std::make_unique<PlainStreamingParser>();
    }
}

} // namespace RawrXD

#endif // RAWRXD_MODEL_REGISTRY_HPP
