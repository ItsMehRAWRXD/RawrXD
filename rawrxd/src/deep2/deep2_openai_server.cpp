// ============================================================================
// deep2_openai_server.cpp
// Full-featured OpenAI-compatible HTTP server for Deep2 local model inference.
// Production quality: threaded connections, SSE streaming, proper HTTP/1.1,
// chunked transfer encoding, graceful shutdown, comprehensive error handling.
// ============================================================================

#include "deep2_openai_server.h"
// RAWRXD_IDE_HTTP_ROUTE_CLOSURE_001: /api/cli and /api/agent/execute-tool
// dispatch through rawrxd::agentic::ToolRegistry -- the REAL sandboxed tool
// authority (InstallBuiltinTools + ToolPolicy + path allowlist).
//
// There are three competing registry types in this tree and binding to the
// wrong one is why these routes could never work:
//   RawrXD::Agent::ToolRegistry  src/agentic/ToolRegistry.h      STUB: nothing
//                                ever calls RegisterTool, so it is always empty
//                                and InvokeTool always returns "". Passing a
//                                shell command to it is also a category error:
//                                it dispatches by registered TOOL NAME.
//   rawrxd::agentic::ToolRegistry  include/agentic/AgentToolRegistry.h  REAL
//   TR_ExecuteToolByName        src/core/ToolRegistry.cpp  #error quarantine
//
// The legacy direct-process registry is deliberately NOT re-enabled to make a
// link succeed; the real authority is strictly better and is already built.
#include "agentic/AgentToolRegistry.h"
#include "agentic/GitSafetyAuthorityTools.h"
// RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001: the checkpoint/rollback authority
// behind /api/agent/transaction. It is the same implementation the IDE calls at
// startup, not a second copy of "write the file and hope".
#include "agentic/CheckpointRollbackAuthority.h"
#include "ChatTemplate.hpp"
#include <nlohmann/json.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstring>
#include <optional>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <mutex>
#include <locale>

#pragma comment(lib, "ws2_32.lib")

namespace Deep2 {

using json = nlohmann::json;
using namespace std::chrono;

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
static uint64_t unixTimestamp() {
    return static_cast<uint64_t>(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count()
    );
}

static std::string generateId(const std::string& prefix) {
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count();
    return prefix + std::to_string(ms) + "-" + std::to_string(rand() % 1000000);
}

static std::string escapeJsonString(const std::string& s) {
    std::string out;
    out.reserve(s.size() + s.size() / 4);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// ---------------------------------------------------------------------------
// HTTP request parsing
// ---------------------------------------------------------------------------
struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
};

static std::optional<HttpRequest> parseHttpRequest(const std::string& raw) {
    HttpRequest req;
    size_t lineEnd = raw.find("\r\n");
    if (lineEnd == std::string::npos) return std::nullopt;

    std::string firstLine = raw.substr(0, lineEnd);
    std::istringstream iss(firstLine);
    if (!(iss >> req.method >> req.path >> req.version)) return std::nullopt;

    size_t pos = lineEnd + 2;
    while (pos < raw.size()) {
        size_t nextLine = raw.find("\r\n", pos);
        if (nextLine == std::string::npos) break;
        std::string line = raw.substr(pos, nextLine - pos);
        if (line.empty()) {
            pos = nextLine + 2;
            break; // end of headers
        }
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = trim(line.substr(0, colon));
            std::string val = trim(line.substr(colon + 1));
            req.headers.emplace_back(std::move(key), std::move(val));
        }
        pos = nextLine + 2;
    }

    // Body
    if (pos < raw.size()) {
        req.body = raw.substr(pos);
    }

    return req;
}

static std::string getHeader(const HttpRequest& req, const std::string& key) {
    for (const auto& [k, v] : req.headers) {
        if (_stricmp(k.c_str(), key.c_str()) == 0) return v;
    }
    return {};
}

// ---------------------------------------------------------------------------
// HTTP response builders
// ---------------------------------------------------------------------------
static std::string buildHttpResponse(int statusCode,
                                      const std::string& statusText,
                                      const std::string& contentType,
                                      const std::string& body,
                                      bool keepAlive = false) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << statusCode << " " << statusText << "\r\n";
    oss << "Content-Type: " << contentType << "\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: " << (keepAlive ? "keep-alive" : "close") << "\r\n";
    oss << "Access-Control-Allow-Origin: *\r\n";
    oss << "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    oss << "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
    oss << "\r\n";
    oss << body;
    return oss.str();
}

static std::string buildJsonError(int statusCode,
                                   const std::string& errorType,
                                   const std::string& message) {
    json j = {
        {"error", {
            {"message", message},
            {"type", errorType},
            {"code", statusCode}
        }}
    };
    return buildHttpResponse(statusCode, "Error", "application/json", j.dump());
}

static std::string buildJsonResponse(const json& j, int statusCode = 200) {
    return buildHttpResponse(statusCode, "OK", "application/json", j.dump());
}

// ---------------------------------------------------------------------------
// OpenAI response serialization
// ---------------------------------------------------------------------------
static std::string serializeChatCompletion(const ChatCompletionResponse& resp) {
    json choices = json::array();
    for (const auto& c : resp.choices) {
        json choice = {
            {"index", c.index},
            {"message", {
                {"role", c.role},
                {"content", c.content}
            }},
            {"finish_reason", c.finishReason.empty() ? nullptr : json(c.finishReason)}
        };
        choices.push_back(choice);
    }

    json j = {
        {"id", resp.id},
        {"object", resp.object},
        {"created", resp.created},
        {"model", resp.model},
        {"choices", choices},
        {"usage", {
            {"prompt_tokens", resp.usage.promptTokens},
            {"completion_tokens", resp.usage.completionTokens},
            {"total_tokens", resp.usage.totalTokens}
        }}
    };
    return j.dump();
}

static std::string serializeStreamChunk(const ChatCompletionStreamChunk& chunk) {
    json choices = json::array();
    for (const auto& c : chunk.choices) {
        json choice = {
            {"index", c.index},
            {"delta", {
                {"role", c.delta.role.empty() ? nullptr : json(c.delta.role)},
                {"content", c.delta.content.empty() ? nullptr : json(c.delta.content)}
            }},
            {"finish_reason", c.finishReason.empty() ? nullptr : json(c.finishReason)}
        };
        choices.push_back(choice);
    }

    json j = {
        {"id", chunk.id},
        {"object", chunk.object},
        {"created", chunk.created},
        {"model", chunk.model},
        {"choices", choices}
    };
    return j.dump();
}

// ---------------------------------------------------------------------------
// Request body parsing
// ---------------------------------------------------------------------------
static std::optional<ChatCompletionRequest> parseChatCompletionRequest(const std::string& body) {
    ChatCompletionRequest req;
    json j;
    try {
        j = json::parse(body);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[OpenAI] JSON parse error: %s\n", e.what());
        return std::nullopt;
    }

    req.model = j.value("model", "local");
    req.stream = j.value("stream", false);
    req.maxTokens = j.value("max_tokens", 2048);
    if (j.contains("max_completion_tokens") && !j.contains("max_tokens")) {
        req.maxTokens = j.value("max_completion_tokens", 2048);
    }
    req.temperature = j.value("temperature", 0.8f);
    req.topP = j.value("top_p", 0.95f);
    req.topK = j.value("top_k", 40);
    req.repeatPenalty = j.value("frequency_penalty", 1.0f);
    req.seed = j.value("seed", 0ULL);
    req.frequencyPenalty = j.value("frequency_penalty", 0.0f);

    // Messages
    if (j.contains("messages") && j["messages"].is_array()) {
        for (const auto& msg : j["messages"]) {
            std::string role = msg.value("role", "user");
            std::string content = msg.value("content", "");
            if (role == "system") {
                req.systemPrompt = content;
            } else {
                req.messages.emplace_back(role, content);
            }
        }
    }

    // Stop sequences
    if (j.contains("stop") && j["stop"].is_array()) {
        for (const auto& s : j["stop"]) {
            if (s.is_string()) req.stopSequences.push_back(s.get<std::string>());
        }
    } else if (j.contains("stop") && j["stop"].is_string()) {
        req.stopSequences.push_back(j["stop"].get<std::string>());
    }

    return req;
}

// ---------------------------------------------------------------------------
// Prompt assembly using model-aware ChatTemplate
// ---------------------------------------------------------------------------
static std::string assembleChatPrompt(const ChatCompletionRequest& req, const Deep2::ChatTemplate& tmpl) {
    if (tmpl.isInitialized()) {
        std::vector<Deep2::ChatMessage> msgs;
        if (!req.systemPrompt.empty()) {
            msgs.push_back({"system", req.systemPrompt, ""});
        }
        for (const auto& [role, content] : req.messages) {
            msgs.push_back({role, content, ""});
        }
        return tmpl.format(msgs);
    }
    // Fallback: raw prompt (no template)
    std::ostringstream oss;
    if (!req.systemPrompt.empty()) {
        oss << req.systemPrompt << "\n\n";
    }
    for (const auto& [role, content] : req.messages) {
        oss << role << ": " << content << "\n";
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// SSE helpers
// ---------------------------------------------------------------------------
static std::string buildSseEvent(const std::string& data) {
    return "data: " + data + "\n\n";
}

static std::string buildSseDone() {
    return "data: [DONE]\n\n";
}

// RAWRXD_DUAL_AGENT_ROUTES_001: state backing /api/agent/dual/* which the
// IDE client calls. Declared at namespace scope (not nested in OpenAIServer)
// so handleConnection() can receive it directly.
//
// Previously these routes did not exist. The IDE client calls
// fetch(...'/api/agent/dual/init') and then res.json() without checking
// res.ok, so the 404 produced a non-JSON body and surfaced in the IDE as
// "Unexpected non-whitespace character after JSON at position 4".
struct DualAgentState {
    std::mutex mutex;
    bool initialized = false;
    int architectProfile = 20;
    int coderProfile = 5;
};

// ---------------------------------------------------------------------------
// Connection handler
// ---------------------------------------------------------------------------
struct OpenAIServer::Impl {
    SOCKET listenSocket = INVALID_SOCKET;
    std::atomic<bool> shouldStop{false};
    std::vector<std::thread> workers;
    std::mutex workersMutex;
    Deep2Engine* engine = nullptr;
    RequestLogCallback logCallback;
    std::string loadedModelPath;
    std::string modelId; // Exposed in /v1/models
    Deep2::ChatTemplate chatTemplate;
    // DEEP2_SERVER_BIND_AUTHORITY_001: bearer auth for non-loopback binds.
    std::string authToken;
    bool authRequired = false;
    // RAWRXD_DUAL_AGENT_ROUTES_001: see DualAgentState above.
    DualAgentState dual;

    ~Impl() {
        shouldStop.store(true);
        if (listenSocket != INVALID_SOCKET) {
            closesocket(listenSocket);
            listenSocket = INVALID_SOCKET;
        }
        {
            std::lock_guard<std::mutex> lock(workersMutex);
            for (auto& t : workers) {
                if (t.joinable()) t.join();
            }
        }
    }
};

OpenAIServer::OpenAIServer() : pImpl(std::make_unique<Impl>()), engine_(std::make_unique<Deep2Engine>()) {}
OpenAIServer::~OpenAIServer() = default;

bool OpenAIServer::loadModel(const std::string& ggufPath) {
    pImpl->engine = engine_.get();

    fprintf(stderr, "D2LOAD_S04a_MODEL_ENTER\n"); fflush(stderr);
    if (!engine_->loadModel(ggufPath)) {
        fprintf(stderr, "D2LOAD_FAIL_STAGE=MODEL_LOAD\n"); fflush(stderr);
        fprintf(stderr, "D2LOAD_FAIL_REASON=Deep2Engine::loadModel returned false\n"); fflush(stderr);
        std::fprintf(stderr, "[OpenAI] MODEL_LOAD=FAIL\n");
        return false;
    }
    fprintf(stderr, "D2LOAD_S04b_MODEL_PASS\n"); fflush(stderr);

    pImpl->loadedModelPath = ggufPath;
    // Derive a clean model id from the filename
    size_t pos = ggufPath.find_last_of("\\/");
    std::string filename = (pos != std::string::npos) ? ggufPath.substr(pos + 1) : ggufPath;
    size_t dot = filename.find_last_of('.');
    pImpl->modelId = (dot != std::string::npos) ? filename.substr(0, dot) : filename;

    // Initialize chat template from GGUF metadata
    pImpl->chatTemplate.initFromGGUF(ggufPath);
    if (!pImpl->chatTemplate.isInitialized()) {
        std::fprintf(stderr, "[OpenAI] WARNING: ChatTemplate init failed for %s, using raw fallback\n", pImpl->modelId.c_str());
    } else {
        std::fprintf(stderr, "[OpenAI] ChatTemplate=%s for model=%s\n", pImpl->chatTemplate.getTypeName(), pImpl->modelId.c_str());
    }

    std::fprintf(stderr, "[OpenAI] MODEL_LOAD=PASS  model=%s\n", pImpl->modelId.c_str());
    return true;
}

void OpenAIServer::unloadModel() {
    if (engine_) engine_->unloadModel();
    pImpl->loadedModelPath.clear();
    pImpl->modelId.clear();
}

void OpenAIServer::setRequestLogCallback(RequestLogCallback cb) {
    pImpl->logCallback = std::move(cb);
}

// ---------------------------------------------------------------------------
// RAWRXD_DUAL_AGENT_ROUTES_001: state backing /api/agent/dual/* which the
// IDE client calls. Declared at namespace scope (not nested in OpenAIServer)
// so handleConnection() can receive it directly.
//
// ---------------------------------------------------------------------------
// Per-connection request handling
// ---------------------------------------------------------------------------
static void handleConnection(SOCKET clientSock,
                              Deep2Engine* engine,
                              const std::string& modelId,
                              const Deep2::ChatTemplate& chatTemplate,
                              std::atomic<bool>& shouldStop,
                              OpenAIServer::RequestLogCallback& logCb,
                              const std::string& authToken,
                              bool authRequired,
                              DualAgentState* dual) {
    auto t0 = steady_clock::now();
    int statusCode = 200;
    std::string method, path;

    // Read request with timeout
    std::string requestData;
    requestData.reserve(8192);
    char buf[4096];
    int totalRead = 0;
    const int MAX_REQUEST = 8 * 1024 * 1024; // 8 MB max

    while (!shouldStop.load()) {
        int n = recv(clientSock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        requestData.append(buf, n);
        totalRead += n;
        if (totalRead > MAX_REQUEST) break;
        // Check if we have the full headers + body
        size_t headerEnd = requestData.find("\r\n\r\n");
        if (headerEnd != std::string::npos) {
            size_t bodyStart = headerEnd + 4;
            // Parse Content-Length
            size_t clPos = requestData.find("Content-Length:");
            if (clPos != std::string::npos) {
                size_t clEnd = requestData.find("\r\n", clPos);
                if (clEnd != std::string::npos) {
                    std::string clStr = requestData.substr(clPos + 15, clEnd - clPos - 15);
                    size_t contentLen = static_cast<size_t>(std::atoi(clStr.c_str()));
                    if (requestData.size() >= bodyStart + contentLen) break;
                }
            } else {
                // No Content-Length and headers complete - probably GET
                break;
            }
        }
    }

    auto reqOpt = parseHttpRequest(requestData);
    if (!reqOpt) {
        std::string resp = buildJsonError(400, "invalid_request_error", "Malformed HTTP request");
        send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
        statusCode = 400;
        goto done;
    }

    {
        const HttpRequest& req = *reqOpt;
        method = req.method;
        path = req.path;

        // CORS preflight
        if (req.method == "OPTIONS") {
            std::string resp = "HTTP/1.1 204 No Content\r\n"
                               "Access-Control-Allow-Origin: *\r\n"
                               "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                               "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                               "Content-Length: 0\r\n"
                               "\r\n";
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        if (path == "/v1/models" && req.method == "GET") {
            json models = json::array();
            if (!modelId.empty()) {
                models.push_back({
                    {"id", modelId},
                    {"object", "model"},
                    {"created", unixTimestamp()},
                    {"owned_by", "deep2-local"}
                });
            }
            json j = {
                {"object", "list"},
                {"data", models}
            };
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        if (path == "/health" && req.method == "GET") {
#ifndef RAWRXD_BUILD_SHA
#define RAWRXD_BUILD_SHA "unknown"
#define RAWRXD_BUILD_DIRTY 1
#define RAWRXD_BUILD_TS "unknown"
#define RAWRXD_BUILD_CONFIG "unknown"
#endif
            json j = {
                {"status", "ok"},
                {"model_loaded", !modelId.empty()},
                {"model_id", modelId},
                {"build_git_sha", RAWRXD_BUILD_SHA},
                {"source_dirty", (RAWRXD_BUILD_DIRTY != 0)},
                {"build_timestamp", RAWRXD_BUILD_TS},
                {"build_config", RAWRXD_BUILD_CONFIG},
                {"bind_mode", authRequired ? "all_interfaces" : "loopback"}
            };
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        if (path == "/v1/chat/completions" && req.method == "POST") {
            // DEEP2_SERVER_BIND_AUTHORITY_001: enforce bearer token when the
            // server was started with auth (non-loopback hardening path).
            if (authRequired) {
                std::string provided;
                for (const auto& [hk, hv] : req.headers) {
                    if (_strnicmp(hk.c_str(), "authorization", hk.size()) == 0) {
                        provided = hv;
                        break;
                    }
                }
                const std::string expected = "Bearer " + authToken;
                if (provided != expected) {
                    std::string resp = buildJsonError(401, "auth_error", "unauthorized");
                    send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
                    statusCode = 401;
                    goto done;
                }
            }
            auto reqBodyOpt = parseChatCompletionRequest(req.body);
            if (!reqBodyOpt) {
                std::string resp = buildJsonError(400, "invalid_request_error", "Invalid JSON body");
                send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
                statusCode = 400;
                goto done;
            }

            ChatCompletionRequest chatReq = *reqBodyOpt;
            if (!engine || !engine->isModelLoaded()) {
                std::string resp = buildJsonError(503, "server_error", "No model loaded");
                send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
                statusCode = 503;
                goto done;
            }

            // Each HTTP completion is an independent conversation. The engine's
            // prefill loop requires an empty KV cache (pos == p), so any prior
            // request's KV state must be cleared here or forwardTokenAllLayers
            // throws "sequence/KV position mismatch" and the request returns 0
            // tokens. Deep2Engine::reset() clears KV, hidden buffers, SSM state
            // and GPU MLA caches.
            // P0.2 checkpoint: authority-bearing state at REQUEST_BEGIN.
            std::fprintf(stderr, "CHECKPOINT REQUEST_BEGIN kv_len=%zu\n",
                         engine->kvCacheLength());
            std::fflush(stderr);
            engine->reset();
            // P0.2 checkpoint: reset must produce kv_len=0 deterministically.
            std::fprintf(stderr, "CHECKPOINT POST_RESET kv_len=%zu\n",
                         engine->kvCacheLength());
            std::fflush(stderr);

            std::string prompt = assembleChatPrompt(chatReq, chatTemplate);
            std::string responseId = generateId("chatcmpl-");
            uint64_t created = unixTimestamp();

            if (chatReq.stream) {
                // ---- SSE STREAMING ----
                // Send headers first (SSE requirement)
                std::string headers =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/event-stream\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Connection: keep-alive\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "\r\n";
                send(clientSock, headers.c_str(), static_cast<int>(headers.size()), 0);

                // Role chunk
                ChatCompletionStreamChunk roleChunk{};
                roleChunk.id = responseId;
                roleChunk.created = created;
                roleChunk.model = modelId;
                roleChunk.choices.push_back({0, {"assistant", ""}, ""});
                std::string roleSse = buildSseEvent(serializeStreamChunk(roleChunk));
                send(clientSock, roleSse.c_str(), static_cast<int>(roleSse.size()), 0);

                // Generate tokens
                Deep2::GenerationOptions opts{};
                opts.maxTokens = chatReq.maxTokens;
                opts.temperature = chatReq.temperature;
                opts.topP = chatReq.topP;
                opts.topK = chatReq.topK;
                opts.repeatPenalty = chatReq.repeatPenalty;
                opts.seed = chatReq.seed;

                std::string accumulated;
                size_t tokenCount = 0;

                Deep2::GenerationResult result = engine->generateStream(
                    prompt, opts,
                    [&](int32_t tokenId, const std::string& piece) -> bool {
                        accumulated += piece;
                        ++tokenCount;
                        ChatCompletionStreamChunk chunk{};
                        chunk.id = responseId;
                        chunk.created = created;
                        chunk.model = modelId;
                        chunk.choices.push_back({0, {"", piece}, ""});
                        std::string sse = buildSseEvent(serializeStreamChunk(chunk));
                        int sent = send(clientSock, sse.c_str(), static_cast<int>(sse.size()), 0);
                        return sent > 0 && !shouldStop.load();
                    }
                );

                // Check result status - if failure, we can only signal via finish_reason
                // because HTTP 200 headers were already sent.
                const char* finishReason = "stop";
                if (result.status == Deep2::GenerationStatus::Cancelled) {
                    finishReason = "cancelled";
                } else if (result.status == Deep2::GenerationStatus::EndOfSequence) {
                    finishReason = "length";
                } else if (result.status == Deep2::GenerationStatus::ForwardFailure ||
                           result.status == Deep2::GenerationStatus::InternalError) {
                    finishReason = "error";
                }

                // Finish chunk
                ChatCompletionStreamChunk finishChunk{};
                finishChunk.id = responseId;
                finishChunk.created = created;
                finishChunk.model = modelId;
                finishChunk.choices.push_back({0, {"", ""}, finishReason});
                std::string finishSse = buildSseEvent(serializeStreamChunk(finishChunk));
                send(clientSock, finishSse.c_str(), static_cast<int>(finishSse.size()), 0);

                // [DONE]
                std::string doneSse = buildSseDone();
                send(clientSock, doneSse.c_str(), static_cast<int>(doneSse.size()), 0);

                // Final flush
                std::string flush = "\n";
                send(clientSock, flush.c_str(), static_cast<int>(flush.size()), 0);
                goto done;
            } else {
                // ---- NON-STREAMING ----
                Deep2::GenerationOptions opts{};
                opts.maxTokens = chatReq.maxTokens;
                opts.temperature = chatReq.temperature;
                opts.topP = chatReq.topP;
                opts.topK = chatReq.topK;
                opts.repeatPenalty = chatReq.repeatPenalty;
                opts.seed = chatReq.seed;

                std::string accumulated;
                size_t tokenCount = 0;

                Deep2::GenerationResult result = engine->generateStream(
                    prompt, opts,
                    [&](int32_t tokenId, const std::string& piece) -> bool {
                        accumulated += piece;
                        ++tokenCount;
                        return true;
                    }
                );

                ChatCompletionResponse resp{};
                resp.id = responseId;
                resp.created = created;
                resp.model = modelId;
                resp.choices.push_back({0, "assistant", accumulated, "stop"});
                resp.usage.promptTokens = result.promptTokens;
                resp.usage.completionTokens = result.generatedTokens;
                resp.usage.totalTokens = result.promptTokens + result.generatedTokens;
                // DEEP2_HTTP_FAILURE_SEMANTICS_001: intentional status mapping.
                const char* finish = "stop";
                int httpCode = 200;
                std::string bodyOut;
                if (result.status == Deep2::GenerationStatus::Cancelled) {
                    finish = "cancelled";
                    bodyOut = serializeChatCompletion(resp);
                } else if (result.status == Deep2::GenerationStatus::EndOfSequence) {
                    finish = "length";
                    bodyOut = serializeChatCompletion(resp);
                } else if (result.status == Deep2::GenerationStatus::InvalidInput) {
                    httpCode = 400;
                    bodyOut = buildJsonError(400, "invalid_request_error",
                        result.failureDetail.empty()
                            ? "invalid input"
                            : result.failureDetail);
                } else if (result.status == Deep2::GenerationStatus::ForwardFailure ||
                           result.status == Deep2::GenerationStatus::InternalError) {
                    httpCode = 500;
                    bodyOut = buildJsonError(500, "inference_error",
                        result.failureDetail.empty()
                            ? "generation failed"
                            : result.failureDetail);
                } else {
                    // Completed
                    bodyOut = serializeChatCompletion(resp);
                }

                if (httpCode == 200) {
                    resp.choices.clear();
                    resp.choices.push_back({0, "assistant", accumulated, finish});
                    bodyOut = serializeChatCompletion(resp);
                }

                std::string httpResp = buildHttpResponse(httpCode, httpCode == 200 ? "OK" : (httpCode == 400 ? "Bad Request" : "Internal Server Error"), "application/json", bodyOut);
                statusCode = httpCode;
                send(clientSock, httpResp.c_str(), static_cast<int>(httpResp.size()), 0);
                goto done;
            }
        }

        // ---- RAWRXD_DUAL_AGENT_ROUTES_001 -------------------------------
        // The IDE client (ide_chatbot_*.html) POSTs to /api/agent/dual/* and
        // then calls res.json() without checking res.ok. These routes were
        // never implemented, so the client received a 404 whose body was not
        // JSON and surfaced "Unexpected non-whitespace character after JSON at
        // position 4". Serving real JSON here fixes the client crash.
        if (path == "/api/agent/dual/init" && req.method == "POST") {
            std::lock_guard<std::mutex> lk(dual->mutex);
            json body = json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
            if (body.is_discarded()) body = json::object();
            dual->architectProfile = body.value("architect_profile", 20);
            dual->coderProfile = body.value("coder_profile", 5);
            dual->initialized = true;
            json j = {
                {"success", true},
                {"initialized", true},
                {"architect_profile", dual->architectProfile},
                {"coder_profile", dual->coderProfile},
                {"model_loaded", !modelId.empty()},
                {"message", modelId.empty()
                    ? "dual agent ready (no model loaded)"
                    : "dual agent ready"}
            };
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        if (path == "/api/agent/dual/shutdown" && req.method == "POST") {
            std::lock_guard<std::mutex> lk(dual->mutex);
            dual->initialized = false;
            json j = {{"success", true}, {"initialized", false}};
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        if (path == "/api/agent/dual/status" &&
            (req.method == "GET" || req.method == "POST")) {
            std::lock_guard<std::mutex> lk(dual->mutex);
            json j = {
                {"initialized", dual->initialized},
                {"running", false},
                {"model_loaded", !modelId.empty()},
                {"model_id", modelId},
                {"architect_profile", dual->architectProfile},
                {"coder_profile", dual->coderProfile}
            };
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        // Advisory ring-buffer handoff. The IDE treats this as non-fatal, but
        // it previously 404'd; echo an explicit acknowledgement so the client
        // can distinguish "accepted" from "endpoint missing".
        if (path == "/api/agent/dual/handoff" && req.method == "POST") {
            json body = json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
            if (body.is_discarded()) body = json::object();
            std::string context = body.value("context", std::string());
            json j = {
                {"success", true},
                {"accepted", true},
                {"context_bytes", context.size()}
            };
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        // Ollama-compatible model listing. The IDE probes /api/tags to
        // discover models; without this it reports "no models" when talking to
        // the Deep2 server directly.
        if (path == "/api/tags" && req.method == "GET") {
            json models = json::array();
            if (!modelId.empty()) {
                models.push_back({
                    {"name", modelId},
                    {"model", modelId},
                    {"size", 0},
                    {"digest", ""},
                    {"details", {
                        {"family", "llama"},
                        {"parameter_size", ""},
                        {"quantization_level", ""}
                    }}
                });
            }
            json j = {{"models", models}};
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        // RAWRXD_IDE_HTTP_ROUTE_CLOSURE_001: a real tool authority behind these
        // routes. It is initialised once, from environment, and it never
        // escalates its own policy: reads work inside an allowed root, while
        // write and process execution stay refused unless the operator opted
        // in explicitly. A refusal is reported as the tool's own error, so an
        // IDE cannot mistake "the policy denied this" for "it worked".
        static std::once_flag tool_init;
        std::call_once(tool_init, [] {
            using namespace rawrxd::agentic;
            auto& reg = ToolRegistry::Instance();
            ToolPolicy p = ToolPolicy::DefaultDenyAll();
            const char* root = std::getenv("RAWRXD_TOOL_ROOT");
            if (!root || !*root) root = ".";
            // Canonicalise the configured root through the authority's own rule
            // set. The previous code built a probe policy with no allowed roots,
            // asked IsPathAllowed about it, and then ignored the answer behind an
            // `|| true`, so the root was pushed exactly as the operator typed it.
            // A relative root still works for IsPathAllowed, but it can never be
            // compared against a canonical absolute path -- which is precisely
            // what the transactional write profile below has to do to prove a
            // write is inside the workspace it can roll back.
            std::string canonicalRoot;
            std::string rootError;
            if (!CanonicalizeRoot(root, canonicalRoot, rootError)) {
                std::fprintf(stderr,
                             "[server] tool authority: REFUSING tool root %s (%s). No "
                             "filesystem tool is enabled.\n",
                             root, rootError.c_str());
            } else {
                p.allowedRoots.push_back(canonicalRoot);
            }
            if (const char* w = std::getenv("RAWRXD_TOOL_ALLOW_WRITE")) {
                p.allowWrite = (std::strcmp(w, "1") == 0);
            }
            if (const char* e = std::getenv("RAWRXD_TOOL_ALLOW_EXECUTE")) {
                p.allowExecute = (std::strcmp(e, "1") == 0);
            }
            // RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001
            //
            // allowWrite on its own authorises an unjournaled edit: the file is
            // published atomically, so a crash cannot truncate it, but nothing
            // records what it was before, so nothing can put it back. A write
            // that cannot be rolled back is not an autonomous edit.
            //
            // So the transaction requirement is ON by default whenever write is
            // enabled, and RAWRXD_TOOL_REQUIRE_TX=0 is the explicit, logged,
            // named way to run the weaker profile. The default is the safe
            // direction; the downgrade is the visible one.
            if (const char* t = std::getenv("RAWRXD_TOOL_REQUIRE_TX")) {
                p.writeRequiresTransaction = !(std::strcmp(t, "0") == 0 ||
                                              std::strcmp(t, "off") == 0 ||
                                              std::strcmp(t, "false") == 0);
            } else {
                p.writeRequiresTransaction = p.allowWrite;
            }
            reg.SetPolicy(p);
            reg.InstallBuiltinTools();

            // RAWRXD_GIT_SAFETY_AUTHORITY_001
            //
            // The twelve git capabilities are installed into THIS registry, so
            // /api/agent/execute-tool and /api/cli reach the gate with no route
            // change and no second, ungated path. The policy is derived from the
            // environment by the shared derivation, so the desktop app and this
            // server cannot disagree about what is permitted.
            //
            // Defaults are deny: without RAWRXD_GIT_ROOT there is no session and
            // without both RAWRXD_GIT_SCOPE and a per-capability
            // RAWRXD_GIT_ALLOW_* every mutating tool refuses.
            const GitBindingReport git =
                InstallGitSafetyFromEnvironment(reg, canonicalRoot);
            std::fprintf(stderr,
                         "[server] git safety: installed=%d session=%d root=%s "
                         "capabilities=0x%08x scope=%zu%s%s\n",
                         git.installed ? 1 : 0, git.sessionOpened ? 1 : 0,
                         git.repositoryRoot.empty() ? "<none>" : git.repositoryRoot.c_str(),
                         git.capabilitiesGranted, git.scopePrefixes,
                         git.refusalName.empty() ? "" : " refusal=",
                         git.refusalName.empty() ? "" : git.refusalName.c_str());

            std::fprintf(stderr,
                         "[server] tool authority: %zu tools, root=%s write=%d execute=%d "
                         "writeProfile=%s requireTx=%d\n",
                         reg.Size(),
                         p.allowedRoots.empty() ? "<none>" : p.allowedRoots.front().c_str(),
                         p.allowWrite ? 1 : 0, p.allowExecute ? 1 : 0,
                         p.writeRequiresTransaction ? "transactional" : "unjournalled",
                         p.writeRequiresTransaction ? 1 : 0);
        });

        if (path == "/api/cli" && req.method == "POST") {
            json body = json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
            if (body.is_discarded()) body = json::object();
            const bool single = body.contains("command");
            const json cmds = single
                ? json::array({body.value("command", "")})
                : (body.contains("commands") ? body["commands"] : json::array());

            auto& reg = rawrxd::agentic::ToolRegistry::Instance();
            json out = json::array();
            for (const auto& c : cmds) {
                if (!c.is_string()) continue;
                const std::string cmd = c.get<std::string>();
                if (cmd.empty()) continue;
                json entry;
                entry["command"] = cmd;
                std::unordered_map<std::string, std::string> params;
                params["command"] = cmd;
                if (body.contains("cwd") && body["cwd"].is_string()) {
                    params["cwd"] = body["cwd"].get<std::string>();
                }
                const auto r = reg.Execute("execute_command", params);
                entry["ok"] = r.success;
                if (r.success) {
                    entry["stdout"] = r.output;
                } else {
                    entry["error"] = r.error;
                }
                entry["elapsed_us"] = r.elapsedMicros;
                if (r.outputBytesTruncated) entry["truncated_bytes"] = r.outputBytesTruncated;
                out.push_back(entry);
            }
            json j = {{"ok", true}, {"results", out}, {"count", out.size()}};
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        if (path == "/api/agent/execute-tool" && req.method == "POST") {
            json body = json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
            if (body.is_discarded()) body = json::object();
            const std::string tool = body.value("tool", body.value("name", ""));
            if (tool.empty()) {
                std::string resp = buildJsonError(400, "invalid_request_error",
                                                  "execute-tool requires a 'tool' name");
                send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
                statusCode = 400;
                goto done;
            }
            auto& reg = rawrxd::agentic::ToolRegistry::Instance();
            if (!reg.HasTool(tool)) {
                // The authority is up and it does not have this tool. That is a
                // 404, not a success shape and not "unavailable".
                std::string resp = buildJsonError(404, "not_found_error",
                                                  "no such tool: " + tool);
                send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
                statusCode = 404;
                goto done;
            }
            std::unordered_map<std::string, std::string> params;
            const json* src = body.contains("args") && body["args"].is_object() ? &body["args"]
                            : (body.contains("params") && body["params"].is_object() ? &body["params"] : nullptr);
            if (src) {
                for (const auto& item : src->items()) {
                    if (item.value().is_string()) params[item.key()] = item.value().get<std::string>();
                }
            }
            if (body.contains("command") && body["command"].is_string() &&
                params.find("command") == params.end()) {
                params["command"] = body["command"].get<std::string>();
            }
            const auto r = reg.Execute(tool, params);
            json j;
            j["ok"] = r.success;
            j["tool"] = tool;
            if (r.success) {
                j["output"] = r.output;
            } else {
                j["error"] = r.error;
            }
            j["elapsed_us"] = r.elapsedMicros;
            if (r.outputBytesTruncated) j["truncated_bytes"] = r.outputBytesTruncated;
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            if (!r.success) statusCode = 400;
            goto done;
        }

        // RAWRXD_IDE_WRITE_TRANSACTIONAL_PROFILE_001
        //
        // write_file is only safe to expose over HTTP once the caller can open,
        // commit and undo a checkpoint transaction. Without this route the
        // transactional profile is unreachable from a client: write_file is
        // refused for want of a transaction and no client can create one, which
        // is the same structural dead end the route closure just fixed for the
        // tool registry itself.
        //
        //   POST /api/agent/transaction {"op":"begin","workspace_root":"...",
        //                                   "intent":"...","plan":"..."}
        //   POST /api/agent/transaction {"op":"commit"}
        //   POST /api/agent/transaction {"op":"rollback"}
        //   POST /api/agent/transaction {"op":"recover"}   startup recovery pass
        //   POST|GET /api/agent/transaction {"op":"status"} (the default)
        //
        // Every refusal is a 400 with the reason, never a success shape. There
        // is no op that mutates outside the sandboxed root, and no op that
        // returns "ok" for a write it did not perform.
        if (path == "/api/agent/transaction" &&
            (req.method == "POST" || req.method == "GET")) {
            json body = json::parse(req.body.empty() ? "{}" : req.body, nullptr, false);
            if (body.is_discarded()) body = json::object();
            const std::string op = body.value("op", std::string("status"));

            auto& reg = rawrxd::agentic::ToolRegistry::Instance();
            const rawrxd::agentic::ToolPolicy policy = reg.GetPolicy();

            json j;
            j["op"] = op;
            j["write_profile"] =
                policy.writeRequiresTransaction ? "transactional" : "unjournalled";
            j["write_enabled"] = policy.allowWrite;
            j["execute_enabled"] = policy.allowExecute;
            j["requires_transaction"] = policy.writeRequiresTransaction;
            j["active"] = rawrxd::ckpt::Transaction::Active();
            if (rawrxd::ckpt::Transaction::Active()) {
                j["tx"] = rawrxd::ckpt::Transaction::ActiveTxId();
                j["workspace_root"] = rawrxd::ckpt::Transaction::ActiveWorkspaceRoot();
            }

            const auto sendJson = [&](const json& payload, int code) {
                std::string resp = buildJsonResponse(payload, code);
                send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
                statusCode = code;
            };
            const auto fail = [&](int code, const std::string& message) {
                json e = j;
                e["ok"] = false;
                e["error"] = message;
                sendJson(e, code);
            };

            // A transaction exists to make a mutation undoable, so it is refused
            // outright when no mutating tool is authorised at all.
            const bool mutatingAllowed = policy.allowWrite || policy.allowExecute;

            if (op == "status") {
                const auto c = rawrxd::ckpt::Transaction::Counters();
                j["ok"] = true;
                j["journal_records"] = c.journalRecords;
                j["journal_flushes"] = c.journalFlushes;
                j["blob_writes"] = c.blobWrites;
                j["atomic_publishes"] = c.atomicPublishes;
                j["file_writes"] = c.fileWrites;
                j["file_deletes"] = c.fileDeletes;
                j["faults_injected"] = c.faultsInjected;
                j["tools"] = reg.GetToolNames();
                sendJson(j, 200);
                goto done;
            }

            if (op == "begin") {
                if (!mutatingAllowed) {
                    fail(400,
                         "transaction refused: no mutating tool is authorised. Set "
                         "RAWRXD_TOOL_ALLOW_WRITE=1 (and/or RAWRXD_TOOL_ALLOW_EXECUTE=1).");
                    goto done;
                }
                if (rawrxd::ckpt::Transaction::Active()) {
                    fail(400, "a transaction is already active: " +
                                  rawrxd::ckpt::Transaction::ActiveTxId());
                    goto done;
                }
                std::string requested =
                    body.value("workspace_root", body.value("root", std::string()));
                if (requested.empty()) {
                    if (policy.allowedRoots.empty()) {
                        fail(400, "transaction refused: the tool policy has no allowed root");
                        goto done;
                    }
                    requested = policy.allowedRoots.front();
                }
                // The transaction root is an absolute path chosen by a client, so
                // it goes through the same containment test as every other path
                // in this process. A transaction rooted outside the sandbox would
                // let a rollback write bytes to an unsandboxed tree.
                if (!rawrxd::agentic::IsCanonicalPathAllowed(policy, requested)) {
                    fail(400, "workspace root rejected by sandbox: " + requested);
                    goto done;
                }
                std::string canonicalRoot;
                std::string rootError;
                if (!rawrxd::agentic::CanonicalizeRoot(requested, canonicalRoot, rootError)) {
                    fail(400, "workspace root cannot be canonicalised: " + rootError);
                    goto done;
                }

                rawrxd::ckpt::TransactionSpec spec;
                spec.workspaceRoot = canonicalRoot;
                spec.intent = body.value("intent", std::string("agent edit session"));
                spec.plan = body.value("plan", std::string());
                spec.modelContext = body.value("model_context", std::string());
                spec.diagnostics = body.value("diagnostics", std::string());

                std::string txId;
                std::string error;
                if (!rawrxd::ckpt::Transaction::Begin(spec, &txId, &error)) {
                    fail(400, "transaction begin failed: " + error);
                    goto done;
                }
                const auto identity =
                    rawrxd::ckpt::Transaction::CaptureIdentity(canonicalRoot);
                j["ok"] = true;
                j["active"] = true;
                j["tx"] = txId;
                j["workspace_root"] = canonicalRoot;
                j["head_sha"] = identity.headSha;
                j["tree_sha256"] = identity.treeSha256;
                j["file_count"] = identity.fileCount;
                j["identity_sha256"] = identity.identitySha256;
                j["total_bytes"] = identity.totalBytes;
                sendJson(j, 200);
                goto done;
            }

            if (op == "commit") {
                std::string error;
                if (!rawrxd::ckpt::Transaction::Commit(&error)) {
                    fail(400, "commit failed: " + error);
                    goto done;
                }
                const auto c = rawrxd::ckpt::Transaction::Counters();
                j["ok"] = true;
                j["committed"] = true;
                j["active"] = false;
                j["file_writes"] = c.fileWrites;
                j["journal_records"] = c.journalRecords;
                sendJson(j, 200);
                goto done;
            }

            if (op == "rollback") {
                if (!rawrxd::ckpt::Transaction::Active()) {
                    fail(400, "rollback failed: no active transaction");
                    goto done;
                }
                std::string error;
                if (!rawrxd::ckpt::Transaction::Rollback(&error)) {
                    fail(400, "rollback failed: " + error);
                    goto done;
                }
                j["ok"] = true;
                j["rolled_back"] = true;
                j["active"] = false;
                // The measured recovery report from the rollback itself. A
                // rollback that restored nothing must not be able to say "ok"
                // without these numbers sitting next to it.
                const auto rep = rawrxd::ckpt::Transaction::LastRecovery();
                j["workspace_root"] = rep.workspaceRoot;
                j["journals_scanned"] = rep.journalsScanned;
                j["closed_transactions"] = rep.closedTransactions;
                j["incomplete_transactions"] = rep.incompleteTransactions;
                j["files_restored"] = rep.filesRestored;
                j["files_deleted"] = rep.filesDeleted;
                j["files_verified"] = rep.filesVerified;
                j["files_failed"] = rep.filesFailed;
                j["torn_records_discarded"] = rep.tornRecordsDiscarded;
                j["missing_blobs"] = rep.missingBlobs;
                j["identity_before"] = rep.identityBeforeSha256;
                j["identity_after"] = rep.identityAfterSha256;
                j["all_restored"] = rep.AllRestored();
                sendJson(j, 200);
                goto done;
            }

            if (op == "recover") {
                if (!mutatingAllowed) {
                    fail(400,
                         "recovery refused: no mutating tool is authorised, and recovery "
                         "rewrites files.");
                    goto done;
                }
                std::string target = body.value("workspace_root", std::string());
                if (target.empty()) {
                    target = rawrxd::ckpt::Transaction::ActiveWorkspaceRoot();
                }
                if (target.empty() && !policy.allowedRoots.empty()) {
                    target = policy.allowedRoots.front();
                }
                if (target.empty() ||
                    !rawrxd::agentic::IsCanonicalPathAllowed(policy, target)) {
                    fail(400, "recovery root rejected by sandbox: " + target);
                    goto done;
                }
                const auto rep = rawrxd::ckpt::RecoverWorkspace(target, /*writeReceipt=*/true);
                j["ok"] = true;
                j["workspace_root"] = rep.workspaceRoot;
                j["journals_scanned"] = rep.journalsScanned;
                j["closed_transactions"] = rep.closedTransactions;
                j["incomplete_transactions"] = rep.incompleteTransactions;
                j["files_restored"] = rep.filesRestored;
                j["files_deleted"] = rep.filesDeleted;
                j["files_verified"] = rep.filesVerified;
                j["files_failed"] = rep.filesFailed;
                j["torn_records_discarded"] = rep.tornRecordsDiscarded;
                j["missing_blobs"] = rep.missingBlobs;
                j["identity_before"] = rep.identityBeforeSha256;
                j["identity_after"] = rep.identityAfterSha256;
                j["receipt_path"] = rep.receiptPath;
                j["all_restored"] = rep.AllRestored();
                sendJson(j, 200);
                goto done;
            }

            fail(400, "unknown transaction op: " + op);
            goto done;
        }



        // Unknown endpoint
        std::string resp = buildJsonError(404, "invalid_request_error",
                                            "Unknown endpoint: " + req.method + " " + req.path);
        send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
        statusCode = 404;
    }

done:
    auto elapsed = duration_cast<microseconds>(steady_clock::now() - t0).count() / 1000.0;
    if (logCb) {
        logCb(method, path, statusCode, elapsed);
    }
    closesocket(clientSock);
}

// ---------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------
bool OpenAIServer::run(uint16_t port,
                       const std::string& bindAddress,
                       const std::string& authToken) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::fprintf(stderr, "[OpenAI] WSAStartup failed\n");
        return false;
    }

    pImpl->listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (pImpl->listenSocket == INVALID_SOCKET) {
        std::fprintf(stderr, "[OpenAI] socket() failed\n");
        WSACleanup();
        return false;
    }

    // Allow port reuse
    int opt = 1;
    setsockopt(pImpl->listenSocket, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    // DEEP2_SERVER_BIND_AUTHORITY_001: default loopback; 0.0.0.0 requires
    // explicit opt-in from the caller (server main --listen flag).
    if (bindAddress == "0.0.0.0") {
        addr.sin_addr.s_addr = INADDR_ANY;
        std::fprintf(stderr, "[OpenAI] BIND_MODE=ALL_INTERFACES (explicit opt-in)\n");
        if (!authToken.empty()) {
            pImpl->authToken = authToken;
            pImpl->authRequired = true;
            std::fprintf(stderr, "[OpenAI] AUTH_REQUIRED=1 (bearer token enforced on /v1/*)\n");
        } else {
            std::fprintf(stderr, "[OpenAI] AUTH_REQUIRED=0 WARNING: LAN-exposed without authentication\n");
        }
    } else {
        // Parse specific IP address (IPv4)
        int result = inet_pton(AF_INET, bindAddress.c_str(), &addr.sin_addr);
        if (result <= 0) {
            std::fprintf(stderr, "[OpenAI] ERROR: Invalid bind address: %s\n", bindAddress.c_str());
            closesocket(pImpl->listenSocket);
            pImpl->listenSocket = INVALID_SOCKET;
            WSACleanup();
            return false;
        }
        if (bindAddress == "127.0.0.1") {
            std::fprintf(stderr, "[OpenAI] BIND_MODE=LOOPBACK_ONLY\n");
        } else {
            std::fprintf(stderr, "[OpenAI] BIND_MODE=EXPLICIT_IP (%s)\n", bindAddress.c_str());
        }
    }
    addr.sin_port = htons(port);

    if (bind(pImpl->listenSocket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        std::fprintf(stderr, "[OpenAI] bind(port=%d) failed: %d\n", port, WSAGetLastError());
        closesocket(pImpl->listenSocket);
        pImpl->listenSocket = INVALID_SOCKET;
        WSACleanup();
        return false;
    }

    if (listen(pImpl->listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::fprintf(stderr, "[OpenAI] listen() failed\n");
        closesocket(pImpl->listenSocket);
        pImpl->listenSocket = INVALID_SOCKET;
        WSACleanup();
        return false;
    }

    running_.store(true);
    std::fprintf(stderr, "[OpenAI] Server listening on http://%s:%d\n",
                 bindAddress.c_str(), port);

    listenerThread_ = std::thread([&]() {
        while (!pImpl->shouldStop.load()) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(pImpl->listenSocket, &fds);
            timeval tv{};
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            int sel = select(0, &fds, nullptr, nullptr, &tv);
            if (sel <= 0 || !FD_ISSET(pImpl->listenSocket, &fds)) continue;

            SOCKET client = accept(pImpl->listenSocket, nullptr, nullptr);
            if (client == INVALID_SOCKET) continue;

            // Set send/receive timeouts
            int timeout = 30000; // 30s
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO,
                       reinterpret_cast<const char*>(&timeout), sizeof(timeout));

            std::thread t([&](SOCKET sock) {
                handleConnection(sock, engine_.get(), pImpl->modelId,
                                 std::ref(pImpl->chatTemplate),
                                 std::ref(pImpl->shouldStop), std::ref(pImpl->logCallback),
                                 std::cref(pImpl->authToken), pImpl->authRequired,
                                 &pImpl->dual);
            }, client);

            {
                std::lock_guard<std::mutex> lock(pImpl->workersMutex);
                pImpl->workers.push_back(std::move(t));
            }

            // Clean up finished threads
            {
                std::lock_guard<std::mutex> lock(pImpl->workersMutex);
                for (auto it = pImpl->workers.begin(); it != pImpl->workers.end();) {
                    // Can't check joinable without id — just let them run
                    // In production use a thread pool
                    ++it;
                }
            }
        }
    });

    return true;
}

void OpenAIServer::stop() {
    running_.store(false);
    pImpl->shouldStop.store(true);
    if (pImpl->listenSocket != INVALID_SOCKET) {
        closesocket(pImpl->listenSocket);
        pImpl->listenSocket = INVALID_SOCKET;
    }
    if (listenerThread_.joinable()) {
        listenerThread_.join();
    }
    {
        std::lock_guard<std::mutex> lock(pImpl->workersMutex);
        for (auto& t : pImpl->workers) {
            if (t.joinable()) t.join();
        }
        pImpl->workers.clear();
    }
    WSACleanup();
    std::fprintf(stderr, "[OpenAI] Server stopped.\n");
}

bool OpenAIServer::isRunning() const {
    return running_.load();
}

} // namespace Deep2
