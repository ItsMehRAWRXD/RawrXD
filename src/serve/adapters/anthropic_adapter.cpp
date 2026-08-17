#include "anthropic_adapter.h"
#include <random>

namespace RawrXD::Serve {

static std::string genMsgId() {
    static std::mt19937_64 rng{std::random_device{}()};
    static const char hex[] = "0123456789abcdef";
    std::string id = "msg_";
    for (int i = 0; i < 24; i++) id += hex[rng() & 0xF];
    return id;
}

bool AnthropicAdapter::match(const std::string& path, const std::string& method) const {
    if (method == "POST" && (path == "/v1/messages" || path == "/v1/messages/"))
        return true;
    return false;
}

GenerateRequest AnthropicAdapter::parseRequest(const std::string& body) const {
    GenerateRequest r;
    r.model       = json::findString(body, "model");
    r.system      = json::findString(body, "system");
    r.messages    = json::findMessages(body);
    r.stream      = json::findBool(body, "stream", true);
    r.temperature = json::findFloat(body, "temperature", 1.0f);
    r.num_predict = json::findInt(body, "max_tokens", 512);
    r.top_p       = json::findFloat(body, "top_p", 0.9f);
    r.top_k       = json::findInt(body, "top_k", 40);

    if (!r.messages.empty()) {
        std::string prompt;
        prompt += r.system.empty() ? "" : (r.system + "\n\n");
        for (auto& m : r.messages) {
            if (m.role == "user")        prompt += "Human: " + m.content + "\n";
            else if (m.role == "assistant") prompt += "Assistant: " + m.content + "\n";
        }
        prompt += "Assistant: ";
        r.prompt = prompt;
    }
    return r;
}

std::string AnthropicAdapter::buildStreamingChunk(
    const std::string& model,
    const GenerationChunk& chunk,
    const GenerateRequest& req) const {
    static thread_local std::string msgId;
    static thread_local int64_t created = 0;
    if (msgId.empty()) {
        msgId = genMsgId();
        created = std::time(nullptr);
    }

    if (chunk.token.empty() && !chunk.done) {
        // message_start
        JsonObj obj;
        obj.kv("type", "message_start");
        obj.kvRaw("message",
            std::string("{\"id\":\"") + msgId +
            "\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"" +
            esc(model) +
            "\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":0,\"output_tokens\":0}}");
        return "event: message_start\ndata: " + obj.build() + "\n\n";
    }

    if (!chunk.token.empty()) {
        JsonObj obj;
        obj.kv("type", "content_block_delta");
        std::ostringstream delta;
        delta << "{\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\""
              << esc(chunk.token) << "\"}}";
        obj.kvRaw("delta", delta.str());
        return "event: content_block_delta\ndata: " + obj.build() + "\n\n";
    }

    if (chunk.done) {
        std::ostringstream s;
        s << "event: message_stop\ndata: "
          << "{\"type\":\"message_stop\"}\n\n";
        msgId.clear();
        return s.str();
    }
    return {};
}

std::string AnthropicAdapter::buildFinalResponse(
    const std::string& model,
    const std::string& fullText,
    const GenerateRequest& req) const {
    JsonObj obj;
    obj.kv("id", genMsgId());
    obj.kv("type", "message");
    obj.kv("role", "assistant");
    obj.kv("model", model);
    std::ostringstream content;
    content << "[{\"type\":\"text\",\"text\":\"" << esc(fullText) << "\"}]";
    obj.kvRaw("content", content.str());
    obj.kv("stop_reason", "end_turn");
    obj.kvRaw("usage", "{\"input_tokens\":0,\"output_tokens\":0}");
    return obj.build();
}

std::string AnthropicAdapter::listModelsJson(const std::vector<ModelEntry>& models) const {
    std::ostringstream s;
    s << "{\"data\":[";
    for (size_t i = 0; i < models.size(); i++) {
        if (i > 0) s << ',';
        s << "{\"id\":\"" << esc(models[i].name) << "\""
          << ",\"type\":\"model\",\"display_name\":\""
          << esc(models[i].name) << "\"}";
    }
    s << "]}";
    return s.str();
}

} // namespace RawrXD::Serve
