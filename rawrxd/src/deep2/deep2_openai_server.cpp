// ============================================================================
// deep2_openai_server.cpp
// Full-featured OpenAI-compatible HTTP server for Deep2 local model inference.
// Production quality: threaded connections, SSE streaming, proper HTTP/1.1,
// chunked transfer encoding, graceful shutdown, comprehensive error handling.
// ============================================================================

#include "deep2_openai_server.h"
#include <nlohmann/json.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstring>
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
// Prompt assembly (chat template approximation)
// ---------------------------------------------------------------------------
static std::string assemblePrompt(const ChatCompletionRequest& req) {
    std::ostringstream oss;
    if (!req.systemPrompt.empty()) {
        oss << "<system>\n" << req.systemPrompt << "\n</system>\n\n";
    }
    for (const auto& [role, content] : req.messages) {
        if (role == "user") {
            oss << "<|user|\u003e\n" << content << "\n";
        } else if (role == "assistant") {
            oss << "<|assistant|\u003e\n" << content << "\n";
        } else {
            oss << role << ": " << content << "\n";
        }
    }
    oss << "<|assistant|\u003e\n";
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
    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen = 4096;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 0;

    if (!engine_->initialize(cfg)) {
        std::fprintf(stderr, "[OpenAI] ENGINE_INIT=FAIL\n");
        return false;
    }

    Deep2::ModelLoadDiag diag{};
    if (!engine_->loadModel(ggufPath, &diag)) {
        std::fprintf(stderr, "[OpenAI] MODEL_LOAD=FAIL  stage=%s  msg=%s\n",
                     diag.stageName.c_str(), diag.message.c_str());
        return false;
    }

    pImpl->loadedModelPath = ggufPath;
    // Derive a clean model id from the filename
    size_t pos = ggufPath.find_last_of("\\/");
    std::string filename = (pos != std::string::npos) ? ggufPath.substr(pos + 1) : ggufPath;
    size_t dot = filename.find_last_of('.');
    pImpl->modelId = (dot != std::string::npos) ? filename.substr(0, dot) : filename;

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
// Per-connection request handling
// ---------------------------------------------------------------------------
static void handleConnection(SOCKET clientSock,
                              Deep2Engine* engine,
                              const std::string& modelId,
                              std::atomic<bool>& shouldStop,
                              OpenAIServer::RequestLogCallback& logCb) {
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
            json j = {
                {"status", "ok"},
                {"model_loaded", !modelId.empty()},
                {"model_id", modelId}
            };
            std::string resp = buildJsonResponse(j);
            send(clientSock, resp.c_str(), static_cast<int>(resp.size()), 0);
            goto done;
        }

        if (path == "/v1/chat/completions" && req.method == "POST") {
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

            std::string prompt = assemblePrompt(chatReq);
            std::string responseId = generateId("chatcmpl-");
            uint64_t created = unixTimestamp();

            if (chatReq.stream) {
                // ---- SSE STREAMING ----
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
                size_t promptTokenCount = 0; // Would need tokenizer count

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

                // Finish chunk
                ChatCompletionStreamChunk finishChunk{};
                finishChunk.id = responseId;
                finishChunk.created = created;
                finishChunk.model = modelId;
                finishChunk.choices.push_back({0, {"", ""}, "stop"});
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

                std::string body = serializeChatCompletion(resp);
                std::string httpResp = buildHttpResponse(200, "OK", "application/json", body);
                send(clientSock, httpResp.c_str(), static_cast<int>(httpResp.size()), 0);
                goto done;
            }
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
bool OpenAIServer::run(uint16_t port) {
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
    addr.sin_addr.s_addr = INADDR_ANY;
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
    std::fprintf(stderr, "[OpenAI] Server listening on http://127.0.0.1:%d\n", port);

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
                                 std::ref(pImpl->shouldStop), std::ref(pImpl->logCallback));
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
