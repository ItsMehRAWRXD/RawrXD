// ============================================================================
// ChatTemplate.cpp -- Model-Aware Chat Template Formatter Implementation
// ============================================================================

#include "ChatTemplate.hpp"
#include "Deep2Engine.h"
#include "GGUFLoader.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>

namespace Deep2 {

// ============================================================================
// Helper: lowercase string
// ============================================================================
static std::string toLower(std::string_view sv) {
    std::string s(sv);
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// ============================================================================
// Template Type Detection
// ============================================================================
ChatTemplateType ChatTemplate::detectFromTemplate(const std::string& templateStr) {
    std::string lower = toLower(templateStr);

    if (lower.find("<|user|>") != std::string::npos &&
        lower.find("<|assistant|>") != std::string::npos) {
        if (lower.find("<|im_start|>") != std::string::npos) return ChatTemplateType::PHI4;
        return ChatTemplateType::PHI3;
    }
    if (lower.find("<|begin_of_text|>") != std::string::npos ||
        lower.find("<|start_header_id|>") != std::string::npos) {
        return ChatTemplateType::LLAMA3;
    }
    if (lower.find("[inst]") != std::string::npos) {
        if (lower.find("<<sys>>") != std::string::npos) return ChatTemplateType::LLAMA2;
        return ChatTemplateType::MISTRAL;
    }
    if (lower.find("<|im_start|>") != std::string::npos) {
        return ChatTemplateType::CHATML;  // Qwen, DeepSeek, etc.
    }
    if (lower.find("<start_of_turn>") != std::string::npos) {
        return ChatTemplateType::GEMMA2;
    }
    if (lower.find("<|start_of_role|>") != std::string::npos) {
        return ChatTemplateType::NEMO;
    }
    if (lower.find("[text]") != std::string::npos && lower.find("[end]") != std::string::npos) {
        return ChatTemplateType::BIGDADDYG;
    }
    if (lower.find("{{prompt}}") != std::string::npos ||
        lower.find("{{user_message}}") != std::string::npos) {
        return ChatTemplateType::CUSTOM;
    }
    return ChatTemplateType::UNKNOWN;
}

ChatTemplateType ChatTemplate::detectFromModel(const std::string& architecture,
                                                const std::string& modelName) {
    std::string arch = toLower(architecture);
    std::string name = toLower(modelName);

    // Phi family
    if (arch.find("phi3") != std::string::npos || name.find("phi3") != std::string::npos ||
        arch.find("phi-3") != std::string::npos || name.find("phi-3") != std::string::npos) {
        return ChatTemplateType::PHI3;
    }
    if (arch.find("phi4") != std::string::npos || name.find("phi4") != std::string::npos ||
        arch.find("phi-4") != std::string::npos || name.find("phi-4") != std::string::npos) {
        return ChatTemplateType::PHI4;
    }

    // Llama family
    if (arch.find("llama3") != std::string::npos || name.find("llama3") != std::string::npos ||
        arch.find("llama-3") != std::string::npos || name.find("llama-3") != std::string::npos) {
        return ChatTemplateType::LLAMA3;
    }
    if (arch.find("llama2") != std::string::npos || name.find("llama2") != std::string::npos ||
        arch.find("llama-2") != std::string::npos || name.find("llama-2") != std::string::npos) {
        return ChatTemplateType::LLAMA2;
    }
    if (arch.find("llama") != std::string::npos || name.find("llama") != std::string::npos) {
        return ChatTemplateType::LLAMA2;  // default llama
    }

    // Mistral family
    if (arch.find("mistral") != std::string::npos || name.find("mistral") != std::string::npos) {
        return ChatTemplateType::MISTRAL;
    }
    if (arch.find("mixtral") != std::string::npos || name.find("mixtral") != std::string::npos) {
        return ChatTemplateType::MIXTRAL;
    }

    // Qwen family
    if (arch.find("qwen3") != std::string::npos || name.find("qwen3") != std::string::npos ||
        arch.find("qwen-3") != std::string::npos || name.find("qwen-3") != std::string::npos) {
        return ChatTemplateType::QWEN3;
    }
    if (arch.find("qwen2.5") != std::string::npos || name.find("qwen2.5") != std::string::npos ||
        arch.find("qwen-2.5") != std::string::npos || name.find("qwen-2.5") != std::string::npos) {
        return ChatTemplateType::QWEN25;
    }
    if (arch.find("qwen2") != std::string::npos || name.find("qwen2") != std::string::npos ||
        arch.find("qwen-2") != std::string::npos || name.find("qwen-2") != std::string::npos ||
        arch.find("qwen") != std::string::npos || name.find("qwen") != std::string::npos) {
        return ChatTemplateType::QWEN2;
    }

    // Gemma family
    if (arch.find("gemma3") != std::string::npos || name.find("gemma3") != std::string::npos ||
        arch.find("gemma-3") != std::string::npos || name.find("gemma-3") != std::string::npos) {
        return ChatTemplateType::GEMMA3;
    }
    if (arch.find("gemma2") != std::string::npos || name.find("gemma2") != std::string::npos ||
        arch.find("gemma-2") != std::string::npos || name.find("gemma-2") != std::string::npos ||
        arch.find("gemma") != std::string::npos || name.find("gemma") != std::string::npos) {
        return ChatTemplateType::GEMMA2;
    }

    // DeepSeek family
    if (arch.find("deepseek") != std::string::npos || name.find("deepseek") != std::string::npos) {
        if (name.find("coder") != std::string::npos) return ChatTemplateType::DEEPSEEK_CODER;
        return ChatTemplateType::DEEPSEEK;
    }

    // Codestral
    if (arch.find("codestral") != std::string::npos || name.find("codestral") != std::string::npos) {
        return ChatTemplateType::CODESTRAL;
    }

    // Nemo
    if (arch.find("nemo") != std::string::npos || name.find("nemo") != std::string::npos) {
        return ChatTemplateType::NEMO;
    }

    // BigDaddyG
    if (name.find("bigdaddyg") != std::string::npos || name.find("bigdaddy") != std::string::npos) {
        return ChatTemplateType::BIGDADDYG;
    }

    return ChatTemplateType::UNKNOWN;
}

const char* ChatTemplate::getTypeName() const {
    switch (config_.type) {
        case ChatTemplateType::RAW_BOS:        return "raw_bos";
        case ChatTemplateType::PHI3:           return "phi3";
        case ChatTemplateType::PHI4:           return "phi4";
        case ChatTemplateType::LLAMA2:         return "llama2";
        case ChatTemplateType::LLAMA3:         return "llama3";
        case ChatTemplateType::MISTRAL:        return "mistral";
        case ChatTemplateType::MIXTRAL:        return "mixtral";
        case ChatTemplateType::QWEN2:          return "qwen2";
        case ChatTemplateType::QWEN25:         return "qwen2.5";
        case ChatTemplateType::QWEN3:          return "qwen3";
        case ChatTemplateType::GEMMA2:         return "gemma2";
        case ChatTemplateType::GEMMA3:         return "gemma3";
        case ChatTemplateType::DEEPSEEK:       return "deepseek";
        case ChatTemplateType::DEEPSEEK_CODER: return "deepseek_coder";
        case ChatTemplateType::CODESTRAL:      return "codestral";
        case ChatTemplateType::NEMO:           return "nemo";
        case ChatTemplateType::CHATML:         return "chatml";
        case ChatTemplateType::BIGDADDYG:      return "bigdaddyg";
        case ChatTemplateType::CUSTOM:         return "custom";
        default:                               return "unknown";
    }
}

// ============================================================================
// Initialization
// ============================================================================
bool ChatTemplate::initFromGGUF(const std::string& ggufPath) {
    // Use the existing GGUFLoader to read metadata
    GGUFLoader loader;
    GGUFLoadOptions opts;
    opts.loadTensors = false;  // Only need metadata
    opts.verbose = false;

    GGUFLoadResult result = GGUFLoader::Load(ggufPath.c_str(), opts);
    if (!result.success) {
        printf("[ChatTemplate] Failed to load GGUF metadata from %s\n", ggufPath.c_str());
        return false;
    }

    const ModelMetadata& meta = result.metadata;
    return initFromMetadata(meta.architecture, "", meta.chatTemplate,
                            meta.bosToken, meta.eosToken);
}

bool ChatTemplate::initFromMetadata(const std::string& architecture,
                                     const std::string& modelName,
                                     const std::string& chatTemplateStr,
                                     const std::string& bosToken,
                                     const std::string& eosToken) {
    config_.bosToken = bosToken.empty() ? "<s>" : bosToken;
    config_.eosToken = eosToken.empty() ? "</s>" : eosToken;

    // First try to detect from the raw template string
    if (!chatTemplateStr.empty()) {
        config_.type = detectFromTemplate(chatTemplateStr);
        if (config_.type != ChatTemplateType::UNKNOWN) {
            if (config_.type == ChatTemplateType::CUSTOM) {
                config_.customTemplate = chatTemplateStr;
            }
            printf("[ChatTemplate] Detected '%s' from template string\n", getTypeName());
            return true;
        }
    }

    // Fall back to architecture + name detection
    config_.type = detectFromModel(architecture, modelName);
    if (config_.type != ChatTemplateType::UNKNOWN) {
        printf("[ChatTemplate] Detected '%s' from model metadata (arch=%s)\n",
               getTypeName(), architecture.c_str());
        return true;
    }

    // Final fallback: raw BOS
    config_.type = ChatTemplateType::RAW_BOS;
    printf("[ChatTemplate] No template detected, using raw_bos fallback\n");
    return true;
}

void ChatTemplate::init(ChatTemplateType type, const ChatTemplateConfig& cfg) {
    config_ = cfg;
    config_.type = type;
}

// ============================================================================
// Formatting
// ============================================================================
std::string ChatTemplate::format(const std::vector<ChatMessage>& messages) const {
    switch (config_.type) {
        case ChatTemplateType::PHI3:           return formatPhi3(messages);
        case ChatTemplateType::PHI4:           return formatPhi4(messages);
        case ChatTemplateType::LLAMA2:         return formatLlama2(messages);
        case ChatTemplateType::LLAMA3:         return formatLlama3(messages);
        case ChatTemplateType::MISTRAL:
        case ChatTemplateType::MIXTRAL:        return formatMistral(messages);
        case ChatTemplateType::QWEN2:
        case ChatTemplateType::QWEN25:
        case ChatTemplateType::QWEN3:          return formatQwen(messages);
        case ChatTemplateType::GEMMA2:
        case ChatTemplateType::GEMMA3:         return formatGemma(messages);
        case ChatTemplateType::DEEPSEEK:
        case ChatTemplateType::DEEPSEEK_CODER: return formatDeepSeek(messages);
        case ChatTemplateType::CODESTRAL:       return formatCodestral(messages);
        case ChatTemplateType::NEMO:           return formatNemo(messages);
        case ChatTemplateType::CHATML:         return formatChatML(messages);
        case ChatTemplateType::BIGDADDYG:       return formatBigDaddyG(messages);
        case ChatTemplateType::CUSTOM:           return formatCustom(messages);
        case ChatTemplateType::RAW_BOS:
        default:                               return formatRawBOS(messages);
    }
}

std::string ChatTemplate::formatSingle(const std::string& userMessage,
                                        const std::string& systemPrompt) const {
    std::vector<ChatMessage> msgs;
    if (!systemPrompt.empty()) {
        msgs.push_back({"system", systemPrompt, ""});
    }
    msgs.push_back({"user", userMessage, ""});
    return format(msgs);
}

std::string ChatTemplate::getAssistantPrefix() const {
    switch (config_.type) {
        case ChatTemplateType::PHI3:           return "<|assistant|>\n";
        case ChatTemplateType::PHI4:           return "<|im_start|>assistant\n";
        case ChatTemplateType::LLAMA3:         return "<|start_header_id|>assistant<|end_header_id|>\n\n";
        case ChatTemplateType::MISTRAL:
        case ChatTemplateType::MIXTRAL:        return " [/INST] ";
        case ChatTemplateType::QWEN2:
        case ChatTemplateType::QWEN25:
        case ChatTemplateType::QWEN3:
        case ChatTemplateType::CHATML:        return "<|im_start|>assistant\n";
        case ChatTemplateType::GEMMA2:
        case ChatTemplateType::GEMMA3:         return "<start_of_turn>model\n";
        case ChatTemplateType::DEEPSEEK:
        case ChatTemplateType::DEEPSEEK_CODER: return "<|im_start|>assistant\n";
        case ChatTemplateType::LLAMA2:         return " [/INST] ";
        case ChatTemplateType::CODESTRAL:      return " [/INST] ";
        case ChatTemplateType::NEMO:           return "<|start_of_role|>assistant<|end_of_role|>";
        case ChatTemplateType::BIGDADDYG:      return "[TEXT]";
        default:                               return "";
    }
}

bool ChatTemplate::isEndOfTurn(const std::string& tokenPiece) const {
    switch (config_.type) {
        case ChatTemplateType::PHI3:
            return tokenPiece == "<|end|>" || tokenPiece == "<|endoftext|>";
        case ChatTemplateType::PHI4:
            return tokenPiece == "<|im_end|>" || tokenPiece == "<|endoftext|>";
        case ChatTemplateType::LLAMA3:
            return tokenPiece == "<|eot_id|>" || tokenPiece == "<|end_of_text|>";
        case ChatTemplateType::MISTRAL:
        case ChatTemplateType::MIXTRAL:
        case ChatTemplateType::CODESTRAL:
        case ChatTemplateType::LLAMA2:
            return tokenPiece == "</s>" || tokenPiece == "[/INST]";
        case ChatTemplateType::QWEN2:
        case ChatTemplateType::QWEN25:
        case ChatTemplateType::QWEN3:
        case ChatTemplateType::CHATML:
        case ChatTemplateType::DEEPSEEK:
        case ChatTemplateType::DEEPSEEK_CODER:
            return tokenPiece == "<|im_end|>";
        case ChatTemplateType::GEMMA2:
        case ChatTemplateType::GEMMA3:
            return tokenPiece == "<end_of_turn>";
        case ChatTemplateType::NEMO:
            return tokenPiece == "<|end_of_text|>";
        case ChatTemplateType::BIGDADDYG:
            return tokenPiece == "[END]";
        default:
            return tokenPiece == config_.eosToken;
    }
}

// ============================================================================
// Per-Format Implementations
// ============================================================================

// -- Phi-3 -----------------------------------------------------------------
// <|system|>You are a helpful assistant<|end|>
// <|user|>Hello<|end|>
// <|assistant|>
std::string ChatTemplate::formatPhi3(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        if (msg.role == "system") {
            out += "<|system|>" + msg.content + "<|end|>";
        } else if (msg.role == "user") {
            out += "<|user|>" + msg.content + "<|end|>";
        } else if (msg.role == "assistant") {
            out += "<|assistant|>" + msg.content + "<|end|>";
        }
    }
    out += "<|assistant|>";
    return out;
}

// -- Phi-4 -----------------------------------------------------------------
// <|im_start|>system
// You are a helpful assistant<|im_end|>
// <|im_start|>user
// Hello<|im_end|>
// <|im_start|>assistant
std::string ChatTemplate::formatPhi4(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        out += "<|im_start|>" + msg.role + "\n" + msg.content + "<|im_end|>";
    }
    out += "<|im_start|>assistant";
    return out;
}

// -- Llama-2 ---------------------------------------------------------------
// <s>[INST] <<SYS>>
// You are a helpful assistant
// <</SYS>>
// Hello [/INST]
std::string ChatTemplate::formatLlama2(const std::vector<ChatMessage>& messages) const {
    std::string out;
    std::string sysPrompt;
    std::vector<std::string> turns;

    for (const auto& msg : messages) {
        if (msg.role == "system") {
            sysPrompt = msg.content;
        } else if (msg.role == "user") {
            turns.push_back(msg.content);
        } else if (msg.role == "assistant") {
            // Llama-2 doesn't have explicit assistant markers in the template
            // The response is just the text after [/INST]
        }
    }

    if (!sysPrompt.empty()) {
        out += "[INST] <<SYS>>\n" + sysPrompt + "\n<</SYS>>\n\n";
    } else {
        out += "[INST] ";
    }

    for (size_t i = 0; i < turns.size(); ++i) {
        if (i > 0) out += " [INST] ";
        out += turns[i] + " [/INST]";
    }
    return out;
}

// -- Llama-3 ---------------------------------------------------------------
// <|begin_of_text|><|start_header_id|>system<|end_header_id|>
// You are a helpful assistant<|eot_id|><|start_header_id|>user<|end_header_id|>
// Hello<|eot_id|><|start_header_id|>assistant<|end_header_id|>
std::string ChatTemplate::formatLlama3(const std::vector<ChatMessage>& messages) const {
    std::string out = "<|begin_of_text|>";
    for (const auto& msg : messages) {
        out += "<|start_header_id|>" + msg.role + "<|end_header_id|>\n\n";
        out += msg.content + "<|eot_id|>";
    }
    out += "<|start_header_id|>assistant<|end_header_id|>\n\n";
    return out;
}

// -- Mistral / Mixtral -----------------------------------------------------
// [INST] Hello [/INST]
std::string ChatTemplate::formatMistral(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        if (msg.role == "system") {
            // Mistral doesn't have a system prompt wrapper; prepend to first user
            // (handled by caller or we can prepend here)
            out += msg.content + " ";
        } else if (msg.role == "user") {
            out += "[INST] " + msg.content + " [/INST]";
        } else if (msg.role == "assistant") {
            out += " " + msg.content + " ";
        }
    }
    return out;
}

// -- Qwen2/2.5/3 -----------------------------------------------------------
// <|im_start|>system
// You are a helpful assistant<|im_end|>
// <|im_start|>user
// Hello<|im_end|>
// <|im_start|>assistant
std::string ChatTemplate::formatQwen(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        out += "<|im_start|>" + msg.role + "\n" + msg.content + "<|im_end|>\n";
    }
    out += "<|im_start|>assistant\n";
    return out;
}

// -- Gemma2/3 --------------------------------------------------------------
// <start_of_turn>user
// Hello<end_of_turn>
// <start_of_turn>model
std::string ChatTemplate::formatGemma(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        std::string turnRole = (msg.role == "assistant" || msg.role == "model") ? "model" : msg.role;
        out += "<start_of_turn>" + turnRole + "\n" + msg.content + "<end_of_turn>\n";
    }
    out += "<start_of_turn>model\n";
    return out;
}

// -- DeepSeek / DeepSeek-Coder ---------------------------------------------
// Same as ChatML/Qwen
std::string ChatTemplate::formatDeepSeek(const std::vector<ChatMessage>& messages) const {
    return formatQwen(messages);
}

// -- Codestral -------------------------------------------------------------
// Same as Mistral
std::string ChatTemplate::formatCodestral(const std::vector<ChatMessage>& messages) const {
    return formatMistral(messages);
}

// -- Nemo ------------------------------------------------------------------
// <|start_of_role|>system<|end_of_role|>You are helpful<|end_of_text|>
// <|start_of_role|>user<|end_of_role|>Hello<|end_of_text|>
// <|start_of_role|>assistant<|end_of_role|>
std::string ChatTemplate::formatNemo(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        out += "<|start_of_role|>" + msg.role + "<|end_of_role|>";
        out += msg.content + "<|end_of_text|>";
    }
    out += "<|start_of_role|>assistant<|end_of_role|>";
    return out;
}

// -- ChatML ----------------------------------------------------------------
// Same as Qwen
std::string ChatTemplate::formatChatML(const std::vector<ChatMessage>& messages) const {
    return formatQwen(messages);
}

// -- BigDaddyG -------------------------------------------------------------
// [TEXT]...[END]
std::string ChatTemplate::formatBigDaddyG(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        if (msg.role == "system") {
            out += "[SYS]" + msg.content + "[END_SYS]";
        } else if (msg.role == "user") {
            out += "[TEXT]" + msg.content + "[END]";
        } else if (msg.role == "assistant") {
            out += "[TEXT]" + msg.content + "[END]";
        }
    }
    out += "[TEXT]";
    return out;
}

// -- Raw BOS ---------------------------------------------------------------
// Just concatenate role: content
std::string ChatTemplate::formatRawBOS(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        out += msg.role + ": " + msg.content + "\n";
    }
    out += "assistant: ";
    return out;
}

// -- Custom (Jinja-style simple substitution) ------------------------------
std::string ChatTemplate::formatCustom(const std::vector<ChatMessage>& messages) const {
    std::string tmpl = config_.customTemplate;
    if (tmpl.empty()) return formatRawBOS(messages);

    // Simple variable substitution (not full Jinja)
    // Extract system prompt
    std::string systemPrompt;
    std::string userMessage;
    for (const auto& msg : messages) {
        if (msg.role == "system") systemPrompt = msg.content;
        if (msg.role == "user") userMessage = msg.content;
    }

    size_t pos = tmpl.find("{{system_prompt}}");
    if (pos != std::string::npos) {
        tmpl.replace(pos, 17, systemPrompt.empty() ? "You are a helpful assistant." : systemPrompt);
    }
    pos = tmpl.find("{{user_message}}");
    if (pos != std::string::npos) {
        tmpl.replace(pos, 16, userMessage);
    }
    pos = tmpl.find("{{content}}");
    if (pos != std::string::npos) {
        tmpl.replace(pos, 11, userMessage);
    }
    pos = tmpl.find("{{prompt}}");
    if (pos != std::string::npos) {
        tmpl.replace(pos, 10, userMessage);
    }

    return tmpl;
}

// ============================================================================
// ChatStreamer Implementation
// ============================================================================
bool ChatStreamer::generate(const std::vector<ChatMessage>& messages,
                             size_t maxTokens,
                             TokenCallback callback) {
    // Format the conversation
    std::string prompt = template_.format(messages);

    // Tokenize
    std::vector<int> promptTokens = engine_.tokenize(prompt);
    if (promptTokens.empty()) {
        printf("[ChatStreamer] ERROR: tokenization produced no tokens\n");
        return false;
    }

    // Generate with streaming callback
    std::vector<int> outputTokens(maxTokens);
    size_t generated = engine_.generate(promptTokens.data(), promptTokens.size(),
                                         outputTokens.data(), maxTokens,
                                         nullptr,
                                         [this, &callback](int tokenId) -> bool {
                                             std::string piece = engine_.detokenize({tokenId});
                                             if (template_.isEndOfTurn(piece)) {
                                                 return false;
                                             }
                                             return callback(tokenId, piece);
                                         });

    // Append assistant response to history
    if (generated > 0) {
        std::string response = engine_.detokenize(
            std::vector<int>(outputTokens.begin(), outputTokens.begin() + generated));
        history_.push_back({"assistant", response, ""});
    }

    return generated > 0;
}

bool ChatStreamer::generateFromPrompt(const std::string& prompt,
                                       size_t maxTokens,
                                       TokenCallback callback) {
    std::vector<int> promptTokens = engine_.tokenize(prompt);
    if (promptTokens.empty()) {
        printf("[ChatStreamer] ERROR: tokenization produced no tokens\n");
        return false;
    }

    std::vector<int> outputTokens(maxTokens);
    size_t generated = engine_.generate(promptTokens.data(), promptTokens.size(),
                                         outputTokens.data(), maxTokens,
                                         nullptr,
                                         [this, &callback](int tokenId) -> bool {
                                             std::string piece = engine_.detokenize({tokenId});
                                             if (template_.isEndOfTurn(piece)) {
                                                 return false;
                                             }
                                             return callback(tokenId, piece);
                                         });

    if (generated > 0) {
        std::string response = engine_.detokenize(
            std::vector<int>(outputTokens.begin(), outputTokens.begin() + generated));
        history_.push_back({"assistant", response, ""});
    }

    return generated > 0;
}

void ChatStreamer::reset() {
    history_.clear();
    engine_.reset();
}

} // namespace Deep2
