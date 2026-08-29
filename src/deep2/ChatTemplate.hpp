// ============================================================================
// ChatTemplate.hpp — Canonical chat-template renderer (Gate 1)
// TinyLlama GGUF jinja (exact):
//   {% for message in messages %}
//   {% if role == user/system/assistant %}
//   {{ '<|ROLE|>\n' + content + eos_token }}
//   {% endif %}
//   {% if loop.last and add_generation_prompt %}
//   {{ '<|assistant|>' }}
//   {% endif %}
//   {% endfor %}
// minja preserves a trailing '\n' after the generation prompt block → '<|assistant|>\n'
// Between messages, a single '\n' follows eos_token (from jinja line structure).
// ============================================================================
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace Deep2 {

struct ChatMessage {
    std::string role;    // "system" | "user" | "assistant"
    std::string content;
};

namespace detail {

inline bool isTinyLlamaFamilyTemplate(std::string_view tmpl) {
    // Matches the GGUF jinja shipped with TinyLlama-1.1B-Chat
    return tmpl.find("<|user|>") != std::string_view::npos &&
           tmpl.find("eos_token") != std::string_view::npos &&
           tmpl.find("add_generation_prompt") != std::string_view::npos;
}

// Exact TinyLlama / Zephyr-style role-tag render (LF only).
inline std::string renderTinyLlama(
    const std::vector<ChatMessage>& messages,
    bool addGenerationPrompt)
{
    static constexpr std::string_view kEos = "</s>";
    std::string out;
    out.reserve(256);
    for (size_t i = 0; i < messages.size(); ++i) {
        const auto& m = messages[i];
        if (m.role == "system") {
            out += "<|system|>\n";
        } else if (m.role == "user") {
            out += "<|user|>\n";
        } else if (m.role == "assistant") {
            out += "<|assistant|>\n";
        } else {
            continue;
        }
        out += m.content;
        out += kEos;
        out += '\n'; // jinja line break after {{ ... eos_token }}
    }
    if (addGenerationPrompt) {
        out += "<|assistant|>\n"; // expression + trailing template newline
    }
    return out;
}

} // namespace detail

inline std::string RenderChatTemplate(
    std::string_view chatTemplate,
    const std::vector<ChatMessage>& messages,
    bool addGenerationPrompt = true)
{
    const bool looksLlama2 =
        chatTemplate.find("[INST]") != std::string_view::npos;
    const bool looksLlama3 =
        chatTemplate.find("<|begin_of_text|>") != std::string_view::npos ||
        chatTemplate.find("<|start_header_id|>") != std::string_view::npos;
    const bool imStart =
        chatTemplate.find("<|im_start|>") != std::string_view::npos;

    auto findRole = [&](std::string_view role) -> const ChatMessage* {
        for (const auto& m : messages) {
            if (m.role == role) return &m;
        }
        return nullptr;
    };

    // TinyLlama GGUF jinja — primary production path for this stack's frozen model.
    if (detail::isTinyLlamaFamilyTemplate(chatTemplate) ||
        (chatTemplate.find("<|user|>") != std::string_view::npos && !imStart && !looksLlama3)) {
        return detail::renderTinyLlama(messages, addGenerationPrompt);
    }

    if (looksLlama3) {
        std::string out = "<|begin_of_text|>";
        for (const auto& m : messages) {
            out += "<|start_header_id|>";
            out += m.role;
            out += "<|end_header_id|>\n\n";
            out += m.content;
            out += "<|eot_id|>";
        }
        if (addGenerationPrompt) {
            out += "<|start_header_id|>assistant<|end_header_id|>\n\n";
        }
        return out;
    }

    if (looksLlama2) {
        const ChatMessage* system = findRole("system");
        const ChatMessage* user = findRole("user");
        std::string out;
        if (system && !system->content.empty()) {
            out = "[INST] <<SYS>>\n";
            out += system->content;
            out += "\n<</SYS>>\n\n";
            if (user) out += user->content;
            out += " [/INST]";
        } else {
            out = "[INST] ";
            if (user) out += user->content;
            out += " [/INST]";
        }
        return out;
    }

    if (imStart) {
        std::string out;
        for (const auto& m : messages) {
            out += "<|im_start|>";
            out += m.role;
            out += "\n";
            out += m.content;
            out += "<|im_end|>\n";
        }
        if (addGenerationPrompt) {
            out += "<|im_start|>assistant\n";
        }
        return out;
    }

    if (chatTemplate.empty()) {
        return detail::renderTinyLlama(messages, addGenerationPrompt);
    }

    // Last resort: placeholder substitution on raw template text.
    std::string result(chatTemplate);
    const ChatMessage* system = findRole("system");
    const ChatMessage* user = findRole("user");
    auto replaceAll = [](std::string& s, std::string_view from, std::string_view to) {
        size_t pos = 0;
        while ((pos = s.find(from, pos)) != std::string::npos) {
            s.replace(pos, from.size(), to);
            pos += to.size();
        }
    };
    if (system) replaceAll(result, "{{system}}", system->content);
    if (user) {
        replaceAll(result, "{{user}}", user->content);
        replaceAll(result, "{{prompt}}", user->content);
    }
    return result;
}

inline std::string RenderChat(
    std::string_view chatTemplate,
    std::string_view systemPrompt,
    std::string_view userPrompt,
    bool addGenerationPrompt = true)
{
    std::vector<ChatMessage> msgs;
    if (!systemPrompt.empty()) {
        msgs.push_back({"system", std::string(systemPrompt)});
    }
    msgs.push_back({"user", std::string(userPrompt)});
    return RenderChatTemplate(chatTemplate, msgs, addGenerationPrompt);
}

} // namespace Deep2
