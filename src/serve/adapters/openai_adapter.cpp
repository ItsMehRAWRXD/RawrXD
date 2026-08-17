#include "openai_adapter.h"
#include <random>
#include <sstream>

namespace RawrXD::Serve {

static std::string genId() {
    static std::mt19937_64 rng{std::random_device{}()};
    static const char hex[] = "0123456789abcdef";
    std::string id = "chatcmpl-";
    for (int i = 0; i < 24; i++) id += hex[rng() & 0xF];
    return id;
}

// Apply Qwen2.5 ChatML template (works for Qwen2.5-Coder-14B and similar).
static std::string flattenMessages(const std::vector<ChatMessage>& msgs,
                                   const std::string& system) {
    std::string out;
    out += "<|im_start|>system\n";
    out += system.empty() ? "You are a helpful assistant." : system;
    out += "<|im_end|>\n";
    for (auto& m : msgs) {
        out += "<|im_start|>" + m.role + "\n" + m.content + "<|im_end|>\n";
    }
    out += "<|im_start|>assistant\n";
    return out;
}

bool OpenAIAdapter::match(const std::string& path, const std::string& method) const {
    if (method == "GET" && (path == "/v1/models" || path == "/v1/models/"))
        return true;
    if (method == "POST" && (path == "/v1/chat/completions" ||
                                  path == "/v1/chat/completions/"))
        return true;
    if (method == "POST" && (path == "/v1/completions" ||
                                  path == "/v1/completions/"))
        return true;
    return false;
}

GenerateRequest OpenAIAdapter::parseRequest(const std::string& body) const {
    GenerateRequest r;
    r.model        = json::findString(body, "model");
    r.messages     = json::findMessages(body);
    r.prompt       = json::findString(body, "prompt");
    r.stream       = json::findBool(body, "stream", true);
    r.temperature  = json::findFloat(body, "temperature", 0.7f);
    r.num_predict  = json::findInt(body, "max_tokens", 512);
    r.top_p        = json::findFloat(body, "top_p", 0.9f);
    r.top_k        = json::findInt(body, "top_k", 40);
    r.repeat_penalty = json::findFloat(body, "frequency_penalty",
                                       json::findFloat(body, "repeat_penalty", 0.0f) + 1.0f);
    if (r.repeat_penalty == 0.0f) r.repeat_penalty = 1.1f;
    r.seed         = json::findInt(body, "seed", -1);
    r.system       = json::findString(body, "system");

    if (r.prompt.empty() && !r.messages.empty()) {
        r.prompt = flattenMessages(r.messages, r.system);
    }
    return r;
}

std::string OpenAIAdapter::buildStreamingChunk(
    const std::string& model,
    const GenerationChunk& chunk,
    const GenerateRequest& req) const {
    static thread_local std::string id;
    if (chunk.token.size() > 0 && id.empty()) id = genId();

    JsonObj obj;
    obj.kv("id", id.empty() ? genId() : id);
    obj.kv("object", "chat.completion.chunk");
    obj.kv("created", static_cast<int64_t>(std::time(nullptr)));
    obj.kv("model", model);

    std::ostringstream choices;
    choices << "{";
    choices << "\"index\":0";
    if (!chunk.token.empty()) {
        choices << ",\"delta\":{\"role\":\"assistant\",\"content\":\""
                << esc(chunk.token) << "\"}";
    } else {
        choices << ",\"delta\":{}";
    }
    if (chunk.done) {
        choices << ",\"finish_reason\":\""
                << (chunk.finish_reason.empty() ? "stop" : esc(chunk.finish_reason))
                << "\"";
    } else {
        choices << ",\"finish_reason\":null";
    }
    choices << "}";
    obj.kvRaw("choices", choices.str());

    return "data: " + obj.build() + "\n\n";
}

std::string OpenAIAdapter::buildFinalResponse(
    const std::string& model,
    const std::string& fullText,
    const GenerateRequest& req) const {
    JsonObj obj;
    obj.kv("id", genId());
    obj.kv("object", "chat.completion");
    obj.kv("created", static_cast<int64_t>(std::time(nullptr)));
    obj.kv("model", model);

    std::ostringstream choices;
    choices << "{";
    choices << "\"index\":0,\"message\":{"
            << "\"role\":\"assistant\","
            << "\"content\":\"" << esc(fullText) << "\""
            << "},\"finish_reason\":\"stop\"";
    choices << "}";
    obj.kvRaw("choices", choices.str());

    std::ostringstream usage;
    usage << "{\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0}";
    obj.kvRaw("usage", usage.str());

    return obj.build();
}

std::string OpenAIAdapter::listModelsJson(const std::vector<ModelEntry>& models) const {
    std::ostringstream s;
    s << "{\"object\":\"list\",\"data\":[";
    for (size_t i = 0; i < models.size(); i++) {
        if (i > 0) s << ',';
        s << "{\"id\":\"" << esc(models[i].name) << "\""
          << ",\"object\":\"model\""
          << ",\"created\":0"
          << ",\"owned_by\":\"rawrxd\"}";
    }
    s << "]}";
    return s.str();
}

} // namespace RawrXD::Serve
