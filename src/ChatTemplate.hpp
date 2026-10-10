// ChatTemplate.hpp -- Model-Aware Chat Template Formatter Interface
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <string_view>
#include <cstdint>
#include <functional>

namespace Deep2 {

// ============================================================================
// Chat Template Type Enum
// ============================================================================
enum class ChatTemplateType {
    NONE = 0,
    RAW_BOS,
    LLAMA2,
    LLAMA3,
    PHI3,
    PHI4,
    MISTRAL,
    MIXTRAL,
    QWEN2,
    QWEN25,
    QWEN3,
    GEMMA2,
    GEMMA3,
    DEEPSEEK,
    DEEPSEEK_CODER,
    CODESTRAL,
    NEMO,
    CHATML,
    BIGDADDYG,
    CUSTOM,
    ZEPHYR,
    YI,
    UNKNOWN
};

// ============================================================================
// Chat Message
// ============================================================================
struct ChatMessage {
    std::string role;      // "system", "user", "assistant", "tool"
    std::string content;   // message content
    std::string name;      // optional name for tool calls
};

// ============================================================================
// Chat Template Configuration
// ============================================================================
struct ChatTemplateConfig {
    ChatTemplateType type = ChatTemplateType::NONE;
    std::string templateStr;      // full template string from tokenizer_config.json
    std::string bosToken;         // beginning of sequence token
    std::string eosToken;         // end of sequence token
    std::string systemPrompt;     // optional system prompt prefix
    bool addGenerationPrompt = true; // add assistant prefix for generation
    std::string customTemplate;   // for CUSTOM type, the raw template string
};

// ============================================================================
// Callback Type for Streaming
// ============================================================================
using TokenCallback = std::function<bool(int tokenId, const std::string& piece)>;

// Forward declaration
class Deep2Engine;

// ============================================================================
// ChatTemplate Class
// ============================================================================
class ChatTemplate {
public:
    ChatTemplate() = default;
    explicit ChatTemplate(const ChatTemplateConfig& cfg);

    // Format a conversation into a single prompt string
    std::string format(const std::vector<ChatMessage>& messages) const;

    // Format with system prompt
    std::string formatWithSystem(const std::vector<ChatMessage>& messages,
                                 const std::string& systemPrompt) const;

    // Format a single user message with optional system prompt
    std::string formatSingle(const std::string& userMessage,
                             const std::string& systemPrompt) const;

    // Get the assistant prefix for this template type
    std::string getAssistantPrefix() const;

    // Check if a token piece signals end of turn
    bool isEndOfTurn(const std::string& tokenPiece) const;

    // Get template type
    ChatTemplateType getType() const { return config_.type; }

    // Get type name string
    const char* getTypeName() const;

    // Get configuration
    const ChatTemplateConfig& getConfig() const { return config_; }

    // Static detection from template string
    static ChatTemplateType detectFromTemplate(const std::string& templateStr);

    // Static detection from model architecture + model name
    static ChatTemplateType detectFromModel(const std::string& architecture,
                                            const std::string& modelName);

    // Initialize from model metadata fields
    bool initFromMetadata(const std::string& architecture,
                          const std::string& modelName,
                          const std::string& chatTemplateStr,
                          const std::string& bosToken,
                          const std::string& eosToken);

    // Initialize with a specific type and config
    void init(ChatTemplateType type, const ChatTemplateConfig& cfg);

    // Load from GGUF file
    bool initFromGGUF(const std::string& ggufPath);

    // Apply template to single user/assistant turn
    std::string applyUserAssistant(const std::string& user,
                                   const std::string& assistant = "") const;

private:
    ChatTemplateConfig config_;
    ChatTemplateType type_ = ChatTemplateType::NONE;

    // Per-format implementations
    std::string formatPhi3(const std::vector<ChatMessage>& messages) const;
    std::string formatPhi4(const std::vector<ChatMessage>& messages) const;
    std::string formatLlama2(const std::vector<ChatMessage>& messages) const;
    std::string formatLlama3(const std::vector<ChatMessage>& messages) const;
    std::string formatMistral(const std::vector<ChatMessage>& messages) const;
    std::string formatQwen(const std::vector<ChatMessage>& messages) const;
    std::string formatGemma(const std::vector<ChatMessage>& messages) const;
    std::string formatDeepSeek(const std::vector<ChatMessage>& messages) const;
    std::string formatCodestral(const std::vector<ChatMessage>& messages) const;
    std::string formatNemo(const std::vector<ChatMessage>& messages) const;
    std::string formatChatML(const std::vector<ChatMessage>& messages) const;
    std::string formatBigDaddyG(const std::vector<ChatMessage>& messages) const;
    std::string formatRawBOS(const std::vector<ChatMessage>& messages) const;
    std::string formatCustom(const std::vector<ChatMessage>& messages) const;
    std::string formatGeneric(const std::vector<ChatMessage>& messages) const;
};

// ============================================================================
// ChatStreamer Class
// ============================================================================
class ChatStreamer {
public:
    ChatStreamer(Deep2Engine& engine, const ChatTemplate& tmpl);

    // Generate with streaming callback
    bool generate(const std::vector<ChatMessage>& messages,
                  size_t maxTokens,
                  TokenCallback callback);

    // Generate from a raw prompt string with streaming callback
    bool generateFromPrompt(const std::string& prompt,
                            size_t maxTokens,
                            TokenCallback callback);

    // Access conversation history
    const std::vector<ChatMessage>& getHistory() const { return history_; }

    // Clear conversation history
    void reset();

private:
    Deep2Engine& engine_;
    ChatTemplate template_;
    std::vector<ChatMessage> history_;
};

} // namespace Deep2

// ============================================================================
// C API for ChatTemplate
// ============================================================================
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
