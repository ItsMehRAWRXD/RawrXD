// HeadlessIDE_GuiRoutes.cpp — R03 thin GUI EngineAPI adapters
#include "HeadlessIDE.h"
#include "ProductGuiRouteAdapters.hpp"
#include <nlohmann/json.hpp>

namespace {

std::string jsonEscapeLocal(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        if (c == '"') o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else o += c;
    }
    return o;
}

HeadlessIDE::AIBackendType mapBackendName(const std::string& raw) {
    const std::string n = ProductGuiRoutes::lower(raw);
    if (n == "deep2" || n == "cpu" || n == "vulkan" || n == "localgguf" ||
        n == "local" || n == "product" || n == "gguf")
        return HeadlessIDE::AIBackendType::LocalGGUF;
    if (n == "ollama") return HeadlessIDE::AIBackendType::Ollama;
    if (n == "openai") return HeadlessIDE::AIBackendType::OpenAI;
    if (n == "claude") return HeadlessIDE::AIBackendType::Claude;
    if (n == "gemini") return HeadlessIDE::AIBackendType::Gemini;
    return HeadlessIDE::AIBackendType::Count;
}

} // namespace

bool HeadlessIDE::routeGuiProductRequest(SOCKET clientFd, const HostedHttpRequest& request,
                                         HostedHttpResponse& response) {
    const std::string& path = request.path;
    using namespace ProductGuiRoutes;

    if (isComplete(path) && request.method == "POST") {
        HostedHttpRequest gen = request;
        gen.path = (path == "/complete/stream") ? "/api/generate/stream" : "/api/generate";
        routeGenerationRequest(clientFd, gen, response);
        return true;
    }
    if (isMetrics(path) && request.method == "GET") {
        response.body = "{\"requests\":" + std::to_string(m_inferenceRequestCount) +
            ",\"tokensPerSec\":0,\"memUsedMB\":0,\"adapter\":\"product_thin\","
            "\"uptimeMs\":" + std::to_string(getUptimeMs()) + "}";
        return true;
    }
    if (isPolicies(path)) {
        response.body = policiesJson(path);
        return true;
    }
    if (isExtensions(path)) {
        response.body = extensionsJson(path, request.method);
        return true;
    }
    if (isExplain(path) && request.method == "GET") {
        response.body = explainJson(path);
        return true;
    }
    if (isBrowse(path)) {
        response.body = browseJson(path);
        return true;
    }
    if (isBackendsUse(path) && request.method == "POST") {
        std::string name;
        try {
            auto j = nlohmann::json::parse(request.body.empty() ? "{}" : request.body);
            name = j.value("backend", j.value("id", ""));
        } catch (...) {
            response.status = 400;
            response.body = "{\"error\":\"invalid_json\"}";
            return true;
        }
        if (name.empty()) {
            response.status = 400;
            response.body = "{\"error\":\"missing_field\",\"message\":\"backend required\"}";
            return true;
        }
        AIBackendType t = mapBackendName(name);
        if (t == AIBackendType::Count) {
            response.status = 400;
            response.body = "{\"error\":\"invalid_backend\",\"backend\":\"" +
                jsonEscapeLocal(name) + "\"}";
            return true;
        }
        if (t == AIBackendType::Ollama ||
            ((t == AIBackendType::OpenAI || t == AIBackendType::Claude ||
              t == AIBackendType::Gemini) && !m_config.allowCloudEgress)) {
            response.status = 422;
            response.body = "{\"success\":false,\"error\":\"LOCAL_ONLY_NO_OLLAMA\","
                "\"message\":\"product backend refuses Ollama/cloud switch\"}";
            return true;
        }
        bool ok = setActiveBackend(t);
        response.status = ok ? 200 : 422;
        response.body = ok
            ? "{\"success\":true,\"active\":\"deep2\",\"backend\":\"LocalGGUF\","
              "\"adapter\":\"product_thin\"}"
            : "{\"success\":false,\"error\":\"switch_failed\"}";
        return true;
    }
    return false;
}
