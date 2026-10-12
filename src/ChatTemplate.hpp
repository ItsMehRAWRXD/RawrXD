// ChatTemplate.hpp -- Model-Aware Chat Template Formatter Interface
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <string_view>
#include <cstdint>

namespace Deep2 {

enum class ChatTemplateType {
    NONE = 0,
    LLAMA2,
    LLAMA3,
    PHI3,
    PHI4,
    MISTRAL,
    CHATML,
    GEMMA2,
    NEMO,
    QWEN2,
    ZEPHYR,
    YI,
    // No template, but the model still needs its BOS token: the raw prompt is
    // sent prefixed with <bos> rather than embedded in a dialogue wrapper.
    RAW_BOS,
    UNKNOWN
};

struct ChatMessage {
    std::string role;      // "system", "user", "assistant", "tool"
    std::string content;   // message content
    std::string name;      // optional name for tool calls
};

struct ChatTemplateConfig {
    ChatTemplateType type = ChatTemplateType::NONE;
    std::string templateStr;      // full template string from tokenizer_config.json
    std::string bosToken;         // beginning of sequence token
    std::string eosToken;         // end of sequence token
    std::string systemPrompt;     // optional system prompt prefix
    bool addGenerationPrompt = true; // add assistant prefix for generation
};

class ChatTemplate {
public:
    ChatTemplate() = default;
    explicit ChatTemplate(const ChatTemplateConfig& cfg);

    // Format a conversation into a single prompt string
    std::string format(const std::vector<ChatMessage>& messages) const;

    // Format with system prompt
    std::string formatWithSystem(const std::vector<ChatMessage>& messages, 
                                  const std::string& systemPrompt) const;

    // Get template type
    ChatTemplateType getType() const { return type_; }

    // ------------------------------------------------------------------------
    // Model-aware initialisation
    // ------------------------------------------------------------------------
    // Build the template from the model's own facts:
    //   arch          GGUF general.architecture ("llama", "qwen2", "gemma2", ...)
    //   systemDefault system prompt to apply when the caller passes none
    //   templateStr   the model's chat template, when it declares one
    //   bos/eos       the model's begin/end-of-sequence token strings
    //
    // Returns false when no template could be resolved at all (arch empty and
    // no templateStr). In that case getType() == UNKNOWN and callers must fall
    // back to the raw prompt. When the architecture is known but the file
    // declares no template, the built-in rule for that architecture is used and
    // RAW_BOS is returned if the only safe wrapper is a bare BOS prefix.
    bool initFromMetadata(const std::string& arch,
                          const std::string& systemDefault,
                          const std::string& templateStr,
                          const std::string& bos,
                          const std::string& eos);

    // ------------------------------------------------------------------------
    // Single-turn formatting and type name
    // ------------------------------------------------------------------------
    // Format exactly one user (or assistant) turn using the detected template.
    std::string formatSingle(const std::string& user, const std::string& assistant = "");

    // Stable, human-readable name of the detected type ("llama3", "chatml", ...).
    const char* getTypeName() const;

    // True when `text` is one of this template's end-of-turn markers (EOS,
    // <|EOT|>, <|eot_id|>, ...). Used to trim generated text.
    bool isEndOfTurn(const std::string& text) const;

    // True when `text` is the model's EOS token (or an equivalent stop marker).
    bool isEos(const std::string& text) const;

    // Get configuration
    const ChatTemplateConfig& getConfig() const { return config_; }

    // Static detection from template string
    static ChatTemplateType detectFromTemplate(const std::string& templateStr);

    // Get tokenizer_config.json chat template from GGUF metadata
    static ChatTemplateConfig fromGGUF(const class GGUFLoader& loader);

    // Apply template to single user/assistant turn
    std::string applyUserAssistant(const std::string& user, const std::string& assistant = "") const;

private:
    ChatTemplateConfig config_;
    ChatTemplateType type_ = ChatTemplateType::NONE;

    std::string formatLLAMA2(const std::vector<ChatMessage>& messages) const;
    std::string formatLLAMA3(const std::vector<ChatMessage>& messages) const;
    std::string formatPHI3(const std::vector<ChatMessage>& messages) const;
    std::string formatPHI4(const std::vector<ChatMessage>& messages) const;
    std::string formatMISTRAL(const std::vector<ChatMessage>& messages) const;
    std::string formatCHATML(const std::vector<ChatMessage>& messages) const;
    std::string formatGEMMA2(const std::vector<ChatMessage>& messages) const;
    std::string formatNEMO(const std::vector<ChatMessage>& messages) const;
    std::string formatQWEN2(const std::vector<ChatMessage>& messages) const;
    std::string formatZEPHYR(const std::vector<ChatMessage>& messages) const;
    std::string formatYI(const std::vector<ChatMessage>& messages) const;
    std::string formatGeneric(const std::vector<ChatMessage>& messages) const;
};

} // namespace Deep2

// C API for ChatTemplate
extern "C" {

// ChatTemplate handle
typedef void* Deep2ChatTemplateHandle;

// Create a chat template from configuration
Deep2ChatTemplateHandle Deep2_ChatTemplate_Create(const char* templateStr);

// Destroy chat template handle
void Deep2_ChatTemplate_Destroy(Deep2ChatTemplateHandle handle);

// Format messages into prompt string
const char* Deep2_ChatTemplate_Format(Deep2ChatTemplateHandle handle, 
                                       const char** roles, 
                                       const char** contents, 
                                       size_t count,
                                       const char* systemPrompt);

// Get last error string
const char* Deep2_ChatTemplate_GetError(void);

} // extern "C"