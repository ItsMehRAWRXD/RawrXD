// ============================================================================
// ChatTemplate.hpp — Model-Aware Chat Template Formatter
// ============================================================================
// Provides chat template formatting for all major model families.
// Detects template style from GGUF metadata and formats multi-turn conversations.
//
// Supported families:
//   Phi-3, Phi-4, Llama-2, Llama-3, Mistral, Mixtral, Qwen2/2.5/3,
//   Gemma2/3, DeepSeek, DeepSeek-Coder, Codestral, Nemo, ChatML
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace Deep2 {

// Forward declarations
class Deep2Engine;

// ============================================================================
// Chat Message
// ============================================================================
struct ChatMessage {
    std::string role;      // "system", "user", "assistant", "tool"
    std::string content;
    std::string name;      // optional: for tool/function names
};

// ============================================================================
// Chat Template Type (detected from GGUF metadata)
// ============================================================================
enum class ChatTemplateType : uint8_t {
    UNKNOWN     = 0,
    RAW_BOS,           // No template, just BOS + raw prompt
    PHI3,              // <|system|>...<|end|><|user|>...<|end|><|assistant|>
    PHI4,              // <|im_start|>system...<|im_end|><|im_start|>user...
    LLAMA2,            // [INST] <<SYS>>...<</SYS>> ... [/INST]
    LLAMA3,            // <|begin_of_text|><|start_header_id|>system...<|end_header_id|>
    MISTRAL,           // [INST] ... [/INST]  (no system prompt wrapper)
    MIXTRAL,           // Same as Mistral
    QWEN2,             // <|im_start|>system\n...<|im_end|>\n<|im_start|>user\n...
    QWEN25,            // Same as Qwen2
    QWEN3,             // Same as Qwen2
    GEMMA2,            // <start_of_turn>user\n...<end_of_turn>\n<start_of_turn>model\n
    GEMMA3,            // Same as Gemma2
    DEEPSEEK,          // <|im_start|>system\n...<|im_end|>\n...
    DEEPSEEK_CODER,    // Same as DeepSeek
    CODESTRAL,         // Mistral format with [INST]...[/INST]
    NEMO,              // <|start_of_role|>system<|end_of_role|>...<|end_of_text|>
    CHATML,            // <|im_start|>system\n...<|im_end|>\n...
    BIGDADDYG,         // [TEXT]...[END] markers
    CUSTOM             // User-provided template string
};

// ============================================================================
// Chat Template Configuration
// ============================================================================
struct ChatTemplateConfig {
    ChatTemplateType type = ChatTemplateType::UNKNOWN;
    std::string customTemplate;   // For CUSTOM type: raw Jinja template
    std::string bosToken = "<s>";
    std::string eosToken = "</s>";
    std::string unkToken = "<unk>";
    int32_t bosTokenId = 1;
    int32_t eosTokenId = 2;
    int32_t unkTokenId = 0;
    bool addBos = true;           // Whether to prepend BOS token
    bool addEos = false;          // Whether to append EOS token to prompt
    bool stripAssistantEos = true;// Strip EOS from assistant responses
};

// ============================================================================
// Chat Template Engine
// ============================================================================
class ChatTemplate {
public:
    ChatTemplate() = default;
    ~ChatTemplate() = default;

    // Initialize from GGUF metadata (auto-detects template type)
    bool initFromGGUF(const std::string& ggufPath);
    bool initFromMetadata(const std::string& architecture,
                          const std::string& modelName,
                          const std::string& chatTemplateStr,
                          const std::string& bosToken = "<s>",
                          const std::string& eosToken = "</s>");

    // Manual initialization with explicit type
    void init(ChatTemplateType type, const ChatTemplateConfig& cfg = {});

    // Format a conversation into a prompt string
    std::string format(const std::vector<ChatMessage>& messages) const;

    // Format a single-turn conversation (convenience)
    std::string formatSingle(const std::string& userMessage,
                              const std::string& systemPrompt = "") const;

    // Get the template type
    ChatTemplateType getType() const { return config_.type; }

    // Get template name for logging
    const char* getTypeName() const;

    // Check if initialized
    bool isInitialized() const { return config_.type != ChatTemplateType::UNKNOWN; }

    // Get config
    const ChatTemplateConfig& getConfig() const { return config_; }

    // Streaming: format just the assistant prefix (for incremental generation)
    std::string getAssistantPrefix() const;

    // Check if a token piece is an end-of-turn marker
    bool isEndOfTurn(const std::string& tokenPiece) const;

    // Detect template type from raw Jinja template string
    static ChatTemplateType detectFromTemplate(const std::string& templateStr);

    // Detect template type from model architecture + name
    static ChatTemplateType detectFromModel(const std::string& architecture,
                                             const std::string& modelName);

private:
    ChatTemplateConfig config_;

    // Per-format formatters
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
};

// ============================================================================
// Streaming Chat Generator
// ============================================================================
class ChatStreamer {
public:
    using TokenCallback = std::function<bool(int32_t tokenId, const std::string& piece)>;

    ChatStreamer(ChatTemplate& tmpl, Deep2Engine& engine)
        : template_(tmpl), engine_(engine) {}

    // Generate a response with streaming output
    // callback receives each token as it's generated; return false to stop
    bool generate(const std::vector<ChatMessage>& messages,
                  size_t maxTokens,
                  TokenCallback callback);

    // Generate from a pre-formatted prompt string
    bool generateFromPrompt(const std::string& prompt,
                            size_t maxTokens,
                            TokenCallback callback);

    // Reset conversation state
    void reset();

    // Get conversation history
    const std::vector<ChatMessage>& getHistory() const { return history_; }

    // Append a message to history
    void appendMessage(const ChatMessage& msg) { history_.push_back(msg); }

private:
    ChatTemplate& template_;
    Deep2Engine& engine_;
    std::vector<ChatMessage> history_;
};

} // namespace Deep2
