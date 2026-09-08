#pragma once
#include "../complete/completion_scheduler.hpp"
#include "../ide/history.hpp"
#include "../ide/session_io.hpp"
#include "../runtime/telemetry.hpp"
#include "../tools/audit_log.hpp"
#include "local_api_json.hpp"
#include "product_deep2_infer.hpp"
#include <string>
namespace rawr::product {

inline std::string LocalApiChatBody(const std::string& model,
                                     const std::string& content) {
    std::string esc;
    JsonEscape(content, esc);
    std::string id = "chatcmpl-rawr";
    return std::string("{\"id\":\"") + id +
           "\",\"object\":\"chat.completion\",\"model\":\"" + model +
           "\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\","
           "\"content\":\"" +
           esc + "\"},\"finish_reason\":\"stop\"}]}";
}

inline std::string LocalApiHandle(const std::string& method,
                                  const std::string& path,
                                  const std::string& body) {
    AuditWrite(AuditRec{"local_api", path.c_str(), 0, 1});
    if (method == "GET" && (path == "/health" || path == "/v1/health"))
        return "{\"status\":\"ok\",\"runtime\":\"deep2\",\"local_only\":1}";
    if (method == "GET" && (path == "/v1/models" || path == "/api/tags"))
        return "{\"object\":\"list\",\"data\":[{\"id\":\"llama32\",\"object\":"
               "\"model\"}]}";
    if (method == "POST" &&
        (path == "/v1/chat/completions" || path == "/v1/completions" ||
         path == "/api/generate")) {
        std::string prompt = JsonString(body, "prompt");
        if (prompt.empty()) prompt = JsonString(body, "content");
        if (prompt.empty()) prompt = "hi";
        std::string model = JsonString(body, "model");
        if (model.empty()) model = "llama32";
        char buf[2048];
        buf[0] = 0;
        bool ok = ::rawr::ProductDeep2Infer(prompt.c_str(), buf, sizeof(buf));
        if (!ok) return "{\"error\":\"generate_failed\"}";
        ProductSession s{};
        s.id = "psess_local_api";
        s.lastPrompt = prompt;
        s.lastText = buf;
        saveSession(s);
        return LocalApiChatBody(model, buf);
    }
    return "{\"error\":\"not_found\"}";
}

} // namespace rawr::product
