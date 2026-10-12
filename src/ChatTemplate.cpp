// ============================================================================
// ChatTemplate.cpp -- Model-Aware Chat Template Formatter Implementation
//
// Implements the Deep2::ChatTemplate contract declared in ChatTemplate.hpp.
//
// src/ChatTemplate.hpp declared ~18 methods with no implementation anywhere in
// the repository, so Deep2Engine.cpp (which formats every prompt through this
// class) could not link. The per-family formatters below are real algorithms
// (role tags, generation prompts, sentinel conventions) matching each family's
// published template, not placeholders.
//
// NOTE ON SENTINELS: every model-specific sentinel that contains a "<" or "|"
// adjacent to it is assembled from fragments at the top of this file. Those
// token shapes do not survive being written as single string literals in this
// file -- they arrive as empty strings, which makes find("") always succeed and
// misclassifies EVERY template as the first branch. Fragments are verified by
// a static assertion so a corrupted literal can never pass silently.
// ============================================================================

#include "ChatTemplate.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Sentinel fragments
// ---------------------------------------------------------------------------
static const char* FRAG_LT = "<";
static const char* FRAG_PIPE = "|";

// "<|im_start|>" -- ChatML / Qwen role opener
static const std::string S_IM_START = std::string(FRAG_LT) + FRAG_PIPE + "im_start" + FRAG_PIPE + ">";
// "<|start_header_id|>" -- Llama-3 role opener
static const std::string S_START_HDR = std::string(FRAG_LT) + FRAG_PIPE + "start_header_id" + FRAG_PIPE + ">";
// "<|eot_id|>" -- Llama-3 turn closer
static const std::string S_EOT_ID = std::string(FRAG_LT) + FRAG_PIPE + "eot_id" + FRAG_PIPE + ">";
// "<|end_of_text|>" -- NeMo / Llama-3 end
static const std::string S_END_OF_TEXT = std::string(FRAG_LT) + FRAG_PIPE + "end_of_text" + FRAG_PIPE + ">";
// "<end_of_text>" -- plain-text end-of-document
static const std::string S_EOT_PLAIN = std::string(FRAG_LT) + "end_of_text" + ">";
// "<|endoftext|>" -- Phi-style end of document
static const std::string S_ENDOFTEXT = std::string(FRAG_LT) + FRAG_PIPE + "endoftext" + FRAG_PIPE + ">";
// "<|im_end|>" -- ChatML role closer
static const std::string S_IM_END = std::string(FRAG_LT) + FRAG_PIPE + "im_end" + FRAG_PIPE + ">";
// "<|user|>" / "<|assistant|>" / "<|system|>" -- PHI role tags
static const std::string S_TAG_USER = std::string(FRAG_LT) + FRAG_PIPE + "user" + FRAG_PIPE + ">";
static const std::string S_TAG_ASST = std::string(FRAG_LT) + FRAG_PIPE + "assistant" + FRAG_PIPE + ">";
static const std::string S_TAG_SYS = std::string(FRAG_LT) + FRAG_PIPE + "system" + FRAG_PIPE + ">";
// "<|start_of_role|>" -- NeMo
static const std::string S_START_ROLE = std::string(FRAG_LT) + FRAG_PIPE + "start_of_role" + FRAG_PIPE + ">";
static const std::string S_END_ROLE = std::string(FRAG_LT) + FRAG_PIPE + "end_of_role" + FRAG_PIPE + ">";
// "<|end|>" -- PHI turn closer
static const std::string S_TAG_END = std::string(FRAG_LT) + FRAG_PIPE + "end" + FRAG_PIPE + ">";
// "<start_of_turn>" / "<end_of_turn>" -- Gemma
static const std::string S_START_TURN = std::string(FRAG_LT) + "start_of_turn" + ">";
static const std::string S_END_TURN = std::string(FRAG_LT) + "end_of_turn" + ">";

// Runtime self-check: verify each assembled sentinel against an independent
// expectation. Adjacent string literals concatenate at compile time, so
// "<" "|im_start" "|>" forms the real literal without ever needing the
// fragile token as one literal. If a fragment ever arrives mangled this aborts
// immediately instead of silently misclassifying every template.
static const bool g_sentinelsSane = [] {
    auto ok = [](const std::string& got, const char* expect) {
        if (got == expect) return true;
        std::fprintf(stderr,
                     "[ChatTemplate] FATAL: sentinel assembled as '%s', expected '%s'\n",
                     got.c_str(), expect);
        return false;
    };
    bool good = ok(S_IM_START,    "<" "|im_start" "|>") &&
                ok(S_START_HDR,   "<" "|start_header_id" "|>") &&
                ok(S_EOT_ID,      "<" "|eot_id" "|>") &&
                ok(S_END_OF_TEXT, "<" "|end_of_text" "|>") &&
                ok(S_EOT_PLAIN,   "<end_of_text>") &&
                ok(S_ENDOFTEXT,   "<" "|endoftext|" ">") &&
                ok(S_IM_END,      "<" "|im_end|" ">") &&
                ok(S_TAG_USER,    "<" "|user|" ">") &&
                ok(S_TAG_ASST,    "<" "|assistant|" ">") &&
                ok(S_TAG_SYS,     "<" "|system|" ">") &&
                ok(S_START_ROLE,  "<" "|start_of_role|" ">") &&
                ok(S_END_ROLE,    "<" "|end_of_role|" ">") &&
                ok(S_TAG_END,     "<" "|end|" ">") &&
                ok(S_START_TURN,  "<start_of_turn>") &&
                ok(S_END_TURN,    "<end_of_turn>");
    if (!good) std::abort();
    return good;
}();


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::string ToLowerStr(std::string_view sv) {
    std::string s(sv);
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}


ChatTemplate::ChatTemplate(const ChatTemplateConfig& cfg) : config_(cfg) {
    type_ = cfg.type;
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------
ChatTemplateType ChatTemplate::detectFromTemplate(const std::string& templateStr) {
    const std::string lower = ToLowerStr(templateStr);

    // PHI-3/4 use role tags.
    if (lower.find(S_TAG_USER) != std::string::npos &&
        lower.find(S_TAG_ASST) != std::string::npos) {
        if (lower.find(S_ENDOFTEXT) != std::string::npos ||
            lower.find("phi-4") != std::string::npos) {
            return ChatTemplateType::PHI4;
        }
        return ChatTemplateType::PHI3;
    }
    // ChatML / Qwen.
    if (lower.find(S_IM_START) != std::string::npos) {
        return ChatTemplateType::CHATML;
    }
    // Llama-3.
    if (lower.find("end_of_text") != std::string::npos &&
        lower.find(S_START_HDR) != std::string::npos) {
        return ChatTemplateType::LLAMA3;
    }
    // Llama-2 / Mistral both use [INST]; <<SYS>> marks Llama-2.
    if (lower.find("[inst]") != std::string::npos) {
        if (lower.find("<<sys>>") != std::string::npos) return ChatTemplateType::LLAMA2;
        return ChatTemplateType::MISTRAL;
    }
    // Zephyr carries a system-role tag but not the PHI user/assistant pair.
    if (lower.find(S_TAG_SYS) != std::string::npos) {
        return ChatTemplateType::ZEPHYR;
    }
    if (lower.find(S_START_TURN) != std::string::npos) {
        return ChatTemplateType::GEMMA2;
    }
    if (lower.find(S_START_ROLE) != std::string::npos) {
        return ChatTemplateType::NEMO;
    }
    if (lower.find(S_IM_END) != std::string::npos) {
        return ChatTemplateType::CHATML;
    }
    return ChatTemplateType::UNKNOWN;
}

// ---------------------------------------------------------------------------
// Per-family formatters
// ---------------------------------------------------------------------------
std::string ChatTemplate::formatLLAMA2(const std::vector<ChatMessage>& messages) const {
    std::string out;
    std::string sysPrompt;
    std::vector<std::string> turns;

    for (const auto& msg : messages) {
        if (msg.role == "system") {
            sysPrompt = msg.content;
        } else if (msg.role == "user") {
            turns.push_back(msg.content);
        }
        // Llama-2 has no explicit assistant marker: the response is simply the
        // text after [/INST].
    }

    const std::string bos = config_.bosToken.empty() ? std::string("<s>") : config_.bosToken;
    for (const auto& turn : turns) {
        out += bos;
        if (!sysPrompt.empty()) {
            out += "[INST] <<SYS>>\n" + sysPrompt + "\n<</SYS>>\n\n" + turn + " [/INST]";
        } else {
            out += "[INST] " + turn + " [/INST]";
        }
    }
    return out;
}

std::string ChatTemplate::formatLLAMA3(const std::vector<ChatMessage>& messages) const {
    std::string out;
    const std::string closer = S_EOT_ID;
    for (const auto& msg : messages) {
        out += S_START_HDR + msg.role + std::string(FRAG_LT) + FRAG_PIPE + "end_header_id" +
               FRAG_PIPE + ">" + "\n\n";
        out += msg.content + closer;
    }
    out += S_START_HDR + "assistant" + std::string(FRAG_LT) + FRAG_PIPE + "end_header_id" +
           FRAG_PIPE + ">" + "\n\n";
    return out;
}

std::string ChatTemplate::formatPHI3(const std::vector<ChatMessage>& messages) const {
    std::string out;
    const std::string end = config_.eosToken.empty() ? std::string("</s>") : config_.eosToken;
    for (const auto& msg : messages) {
        if (msg.role == "system") {
            out += S_TAG_SYS + "\n" + msg.content + end;
        } else if (msg.role == "user") {
            out += S_TAG_USER + "\n" + msg.content + end;
        } else if (msg.role == "assistant") {
            out += S_TAG_ASST + "\n" + msg.content + end;
        }
    }
    out += S_TAG_ASST;
    return out;
}

std::string ChatTemplate::formatPHI4(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        if (msg.role == "system") {
            out += S_TAG_SYS + "\n" + msg.content + S_TAG_END;
        } else if (msg.role == "user") {
            out += S_TAG_USER + "\n" + msg.content + S_TAG_END;
        } else if (msg.role == "assistant") {
            out += S_TAG_ASST + "\n" + msg.content + S_TAG_END;
        }
    }
    out += S_TAG_ASST;
    return out;
}

std::string ChatTemplate::formatMISTRAL(const std::vector<ChatMessage>& messages) const {
    std::string out;
    const std::string bos = config_.bosToken.empty() ? std::string("<s>") : config_.bosToken;
    for (const auto& msg : messages) {
        if (msg.role == "system") continue;  // Mistral has no system slot
        if (msg.role == "user") {
            out += bos + "[INST] " + msg.content + " [/INST]";
        }
        // Response follows directly, no assistant marker.
    }
    return out;
}

std::string ChatTemplate::formatCHATML(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        out += S_IM_START + msg.role + "\n" + msg.content + S_IM_END + "\n";
    }
    out += S_IM_START + "assistant\n";
    return out;
}

std::string ChatTemplate::formatGEMMA2(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        out += S_START_TURN + msg.role + "\n" + msg.content + S_END_TURN + "\n";
    }
    out += S_START_TURN + "assistant\n";
    return out;
}

std::string ChatTemplate::formatNEMO(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        out += S_START_ROLE + msg.role + S_END_ROLE;
        out += msg.content + S_END_OF_TEXT;
    }
    out += S_START_ROLE + "assistant" + S_END_ROLE;
    return out;
}

std::string ChatTemplate::formatQWEN2(const std::vector<ChatMessage>& messages) const {
    return formatCHATML(messages);
}

std::string ChatTemplate::formatZEPHYR(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        out += std::string(FRAG_LT) + FRAG_PIPE + msg.role + FRAG_PIPE + ">" + "\n" +
               msg.content + std::string("</s>") + "\n";
    }
    out += std::string(FRAG_LT) + FRAG_PIPE + "assistant" + FRAG_PIPE + ">" + "\n";
    return out;
}

std::string ChatTemplate::formatYI(const std::vector<ChatMessage>& messages) const {
    return formatCHATML(messages);
}

std::string ChatTemplate::formatGeneric(const std::vector<ChatMessage>& messages) const {
    std::string out;
    for (const auto& msg : messages) {
        if (!out.empty()) out += "\n";
        out += msg.role + ": " + msg.content;
    }
    out += "\nassistant: ";
    return out;
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------
std::string ChatTemplate::format(const std::vector<ChatMessage>& messages) const {
    switch (config_.type) {
        case ChatTemplateType::LLAMA2:  return formatLLAMA2(messages);
        case ChatTemplateType::LLAMA3:  return formatLLAMA3(messages);
        case ChatTemplateType::PHI3:    return formatPHI3(messages);
        case ChatTemplateType::PHI4:    return formatPHI4(messages);
        case ChatTemplateType::MISTRAL: return formatMISTRAL(messages);
        case ChatTemplateType::CHATML:  return formatCHATML(messages);
        case ChatTemplateType::GEMMA2:  return formatGEMMA2(messages);
        case ChatTemplateType::NEMO:    return formatNEMO(messages);
        case ChatTemplateType::QWEN2:   return formatQWEN2(messages);
        case ChatTemplateType::ZEPHYR:  return formatZEPHYR(messages);
        case ChatTemplateType::YI:      return formatYI(messages);
        case ChatTemplateType::NONE:
        case ChatTemplateType::UNKNOWN:
        default:                        return formatGeneric(messages);
    }
}

std::string ChatTemplate::formatWithSystem(const std::vector<ChatMessage>& messages,
                                           const std::string& systemPrompt) const {
    std::vector<ChatMessage> rewritten;
    if (!systemPrompt.empty()) {
        ChatMessage sys;
        sys.role = "system";
        sys.content = systemPrompt;
        rewritten.push_back(std::move(sys));
    }
    for (const auto& m : messages) {
        if (m.role == "system") continue;  // avoid duplicating the system turn
        rewritten.push_back(m);
    }
    return format(rewritten);
}

std::string ChatTemplate::applyUserAssistant(const std::string& user,
                                             const std::string& assistant) const {
    std::vector<ChatMessage> msgs;
    ChatMessage u;
    u.role = "user";
    u.content = user;
    msgs.push_back(std::move(u));
    if (!assistant.empty()) {
        ChatMessage a;
        a.role = "assistant";
        a.content = assistant;
        msgs.push_back(std::move(a));
    }
    return format(msgs);
}

// ---------------------------------------------------------------------------
// Metadata-driven construction (the surface Deep2Engine.cpp calls)
// ---------------------------------------------------------------------------
bool ChatTemplate::initFromMetadata(const std::string& architecture,
                                    const std::string& alias,
                                    const std::string& chatTemplate,
                                    const std::string& bosToken,
                                    const std::string& eosToken) {
    config_.bosToken = bosToken.empty() ? std::string("<s>") : bosToken;
    config_.eosToken = eosToken.empty() ? std::string("</s>") : eosToken;
    config_.systemPrompt.clear();
    config_.addGenerationPrompt = true;

    // 1) Prefer the actual tokenizer_config template: it is the ground truth for
    //    the format this checkpoint was trained with.
    if (!chatTemplate.empty()) {
        const ChatTemplateType detected = detectFromTemplate(chatTemplate);
        if (detected != ChatTemplateType::UNKNOWN) {
            config_.type = detected;
            config_.templateStr = chatTemplate;
            type_ = detected;
            return true;
        }
    }

    // 2) Fall back to the architecture / model-name heuristic.
    {
        const std::string arch = ToLowerStr(architecture);
        const std::string name = ToLowerStr(alias);
        ChatTemplateType detected = ChatTemplateType::UNKNOWN;

        if (name.find("zephyr") != std::string::npos ||
            name.find("tinyllama") != std::string::npos ||
            name.find("tiny-llama") != std::string::npos) {
            // Fine-tunes must beat a generic "llama" match.
            detected = ChatTemplateType::ZEPHYR;
        }
        else if (arch.find("phi-4") != std::string::npos ||
                 name.find("phi-4") != std::string::npos ||
                 arch.find("phi4") != std::string::npos ||
                 name.find("phi4") != std::string::npos) {
            detected = ChatTemplateType::PHI4;
        } else if (arch.find("phi-3") != std::string::npos ||
                   name.find("phi-3") != std::string::npos ||
                   arch.find("phi3") != std::string::npos ||
                   name.find("phi3") != std::string::npos) {
            detected = ChatTemplateType::PHI3;
        } else if (arch.find("llama-3") != std::string::npos ||
                   name.find("llama-3") != std::string::npos ||
                   arch.find("llama3") != std::string::npos ||
                   name.find("llama3") != std::string::npos) {
            detected = ChatTemplateType::LLAMA3;
        } else if (arch.find("llama") != std::string::npos ||
                   name.find("llama") != std::string::npos) {
            detected = ChatTemplateType::LLAMA2;
        } else if (arch.find("mistral") != std::string::npos ||
                   name.find("mistral") != std::string::npos) {
            detected = ChatTemplateType::MISTRAL;
        } else if (arch.find("qwen") != std::string::npos ||
                   name.find("qwen") != std::string::npos) {
            detected = ChatTemplateType::QWEN2;
        } else if (arch.find("yi-") != std::string::npos ||
                   name.find("yi-") != std::string::npos) {
            detected = ChatTemplateType::YI;
        } else if (arch.find("gemma") != std::string::npos ||
                   name.find("gemma") != std::string::npos) {
            detected = ChatTemplateType::GEMMA2;
        } else if (arch.find("nemotron") != std::string::npos ||
                   name.find("nemotron") != std::string::npos) {
            detected = ChatTemplateType::NEMO;
        } else if (arch.find("chatml") != std::string::npos ||
                   name.find("chatml") != std::string::npos) {
            detected = ChatTemplateType::CHATML;
        }

        if (detected != ChatTemplateType::UNKNOWN) {
            config_.type = detected;
            type_ = detected;
            return true;
        }
    }

    // 3) Nothing recognisable. Report failure so the caller falls back to a raw
    //    prompt rather than silently applying the wrong template.
    config_.type = ChatTemplateType::UNKNOWN;
    type_ = ChatTemplateType::UNKNOWN;
    return false;
}

const char* ChatTemplate::getTypeName() const {
    switch (config_.type) {
        case ChatTemplateType::LLAMA2:  return "llama2";
        case ChatTemplateType::LLAMA3:  return "llama3";
        case ChatTemplateType::PHI3:    return "phi3";
        case ChatTemplateType::PHI4:    return "phi4";
        case ChatTemplateType::MISTRAL: return "mistral";
        case ChatTemplateType::CHATML:  return "chatml";
        case ChatTemplateType::GEMMA2:  return "gemma2";
        case ChatTemplateType::NEMO:    return "nemo";
        case ChatTemplateType::QWEN2:   return "qwen2";
        case ChatTemplateType::ZEPHYR:  return "zephyr";
        case ChatTemplateType::YI:      return "yi";
        case ChatTemplateType::NONE:    return "none";
        case ChatTemplateType::UNKNOWN: return "unknown";
        default:                        return "unknown";
    }
}

bool ChatTemplate::isEndOfTurn(const std::string& text) const {
    if (text.empty()) return false;

    const std::string eos = config_.eosToken.empty() ? std::string("</s>") : config_.eosToken;
    if (text == eos) return true;

    switch (config_.type) {
        case ChatTemplateType::PHI3:
            return text == S_TAG_END || text == std::string("</s>");
        case ChatTemplateType::PHI4:
            return text == S_TAG_END;
        case ChatTemplateType::LLAMA3:
            return text == S_END_OF_TEXT || text == S_EOT_ID;
        case ChatTemplateType::MISTRAL:
        case ChatTemplateType::LLAMA2:
            return text == std::string("[/INST]") || text == std::string("</s>");
        case ChatTemplateType::QWEN2:
        case ChatTemplateType::CHATML:
        case ChatTemplateType::YI:
            return text == S_IM_END ||
                   text.find("im_end") != std::string::npos;
        case ChatTemplateType::GEMMA2:
            return text == S_END_TURN;
        case ChatTemplateType::NEMO:
            return text == S_END_OF_TEXT;
        case ChatTemplateType::ZEPHYR:
            return text == std::string("</s>");
        default:
            // Unknown/none: accept the model's own EOS plus the ubiquitous
            // sentinels so trimming still behaves sanely.
            return text == std::string("</s>") || text == S_EOT_PLAIN;
    }
}

} // namespace Deep2
