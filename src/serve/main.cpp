// ============================================================================
// rawrxd-serve — Universal wire format HTTP server for RawrXD
// No Ollama. OpenAI + Anthropic + RawrXD-native health endpoint.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <http.h>

#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <csignal>
#include <chrono>

#pragma comment(lib, "httpapi.lib")

#include "wire_format.h"
#include "inference_backend.h"
#include "adapters/openai_adapter.h"
#include "adapters/anthropic_adapter.h"

using namespace RawrXD::Serve;

namespace {

constexpr ULONG REQ_BUF_SIZE = 64 * 1024;

struct GlobalState {
    std::vector<std::unique_ptr<WireFormatAdapter>> adapters;
    InferenceBackend* backend = nullptr;
    HTTP_SERVER_SESSION_ID sessionId = 0;
    HTTP_URL_GROUP_ID urlGroupId = 0;
    HANDLE reqQueue = nullptr;
    USHORT port = 8080;
    std::atomic<bool> running{false};
    std::thread listener;
};

GlobalState G;

std::string extractPath(HTTP_REQUEST* req) {
    std::wstring wpath(req->CookedUrl.pAbsPath,
                       req->CookedUrl.AbsPathLength / sizeof(WCHAR));
    std::string path(wpath.begin(), wpath.end());
    auto q = path.find('?');
    if (q != std::string::npos) path.resize(q);
    return path;
}

std::string extractMethod(HTTP_REQUEST* req) {
    switch (req->Verb) {
        case HttpVerbGET:    return "GET";
        case HttpVerbPOST:   return "POST";
        case HttpVerbPUT:    return "PUT";
        case HttpVerbDELETE: return "DELETE";
        case HttpVerbHEAD:   return "HEAD";
        default:             return "OTHER";
    }
}

std::string readBody(HTTP_REQUEST* req) {
    std::string body;
    if (req->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS) {
        std::vector<char> buf(4096);
        ULONG bytesRead = 0;
        while (true) {
            ULONG ret = HttpReceiveRequestEntityBody(
                G.reqQueue, req->RequestId, 0,
                buf.data(), static_cast<ULONG>(buf.size()),
                &bytesRead, nullptr);
            if (ret == NO_ERROR && bytesRead > 0) {
                body.append(buf.data(), bytesRead);
            } else {
                break;
            }
        }
    }
    for (USHORT i = 0; i < req->EntityChunkCount; i++) {
        auto& c = req->pEntityChunks[i];
        if (c.DataChunkType == HttpDataChunkFromMemory && c.FromMemory.BufferLength > 0) {
            body.append(static_cast<char*>(c.FromMemory.pBuffer),
                       c.FromMemory.BufferLength);
        }
    }
    return body;
}

void sendSimple(HTTP_REQUEST* req, USHORT status,
                const std::string& contentType,
                const std::string& body) {
    HTTP_RESPONSE r = {};
    r.StatusCode = status;
    r.pReason = (status == 200) ? "OK"
                : (status == 400) ? "Bad Request"
                : (status == 404) ? "Not Found"
                : (status == 405) ? "Method Not Allowed"
                : (status == 503) ? "Service Unavailable"
                : "Internal Server Error";
    r.ReasonLength = static_cast<USHORT>(std::strlen(r.pReason));

    HTTP_KNOWN_HEADER& ct = r.Headers.KnownHeaders[HttpHeaderContentType];
    ct.pRawValue = contentType.c_str();
    ct.RawValueLength = static_cast<USHORT>(contentType.size());

    HTTP_DATA_CHUNK chunk = {};
    chunk.DataChunkType = HttpDataChunkFromMemory;
    chunk.FromMemory.pBuffer = (PVOID)body.data();
    chunk.FromMemory.BufferLength = static_cast<ULONG>(body.size());

    r.EntityChunkCount = 1;
    r.pEntityChunks = &chunk;

    HttpSendHttpResponse(G.reqQueue, req->RequestId, 0,
                         &r, nullptr, nullptr, nullptr, 0, nullptr, nullptr);
}

void sendStreamStart(HTTP_REQUEST* req, const std::string& contentType,
                     const std::string& firstChunk) {
    HTTP_RESPONSE r = {};
    r.StatusCode = 200;
    r.pReason = "OK";
    r.ReasonLength = 2;

    HTTP_KNOWN_HEADER& ct = r.Headers.KnownHeaders[HttpHeaderContentType];
    ct.pRawValue = contentType.c_str();
    ct.RawValueLength = static_cast<USHORT>(contentType.size());

    HTTP_KNOWN_HEADER& te = r.Headers.KnownHeaders[HttpHeaderTransferEncoding];
    te.pRawValue = "chunked";
    te.RawValueLength = 7;

    ULONG ret = HttpSendHttpResponse(G.reqQueue, req->RequestId,
        HTTP_SEND_RESPONSE_FLAG_MORE_DATA,
        &r, nullptr, nullptr, nullptr, 0, nullptr, nullptr);
    if (ret != NO_ERROR) return;

    if (!firstChunk.empty()) {
        HTTP_DATA_CHUNK chunk = {};
        chunk.DataChunkType = HttpDataChunkFromMemory;
        chunk.FromMemory.pBuffer = (PVOID)firstChunk.data();
        chunk.FromMemory.BufferLength = static_cast<ULONG>(firstChunk.size());
        HttpSendResponseEntityBody(G.reqQueue, req->RequestId,
            HTTP_SEND_RESPONSE_FLAG_MORE_DATA,
            1, &chunk, nullptr, nullptr, 0, nullptr, nullptr);
    }
}

void sendStreamMore(HTTP_REQUEST* req, const std::string& body, bool done) {
    HTTP_DATA_CHUNK chunk = {};
    chunk.DataChunkType = HttpDataChunkFromMemory;
    chunk.FromMemory.pBuffer = (PVOID)body.data();
    chunk.FromMemory.BufferLength = static_cast<ULONG>(body.size());
    ULONG flags = done ? 0 : HTTP_SEND_RESPONSE_FLAG_MORE_DATA;
    HttpSendResponseEntityBody(G.reqQueue, req->RequestId, flags,
        1, &chunk, nullptr, nullptr, 0, nullptr, nullptr);
}

void handleRequest(HTTP_REQUEST* req) {
    auto path = extractPath(req);
    auto method = extractMethod(req);

    // RawrXD-native health endpoint
    if (path == "/health" || path == "/health/") {
        sendSimple(req, 200, "application/json",
            R"({"status":"ok","engine":"rawrxd","version":"1.0"})");
        return;
    }

    // Find matching adapter
    WireFormatAdapter* adapter = nullptr;
    for (auto& a : G.adapters) {
        if (a->match(path, method)) { adapter = a.get(); break; }
    }
    if (!adapter) {
        sendSimple(req, 404, "application/json",
            R"({"error":"not found","supported":["/v1/chat/completions","/v1/completions","/v1/models","/v1/messages","/health"]})");
        return;
    }

    // GET = model list
    if (method == "GET") {
        std::vector<ModelEntry> models;
        if (G.backend && G.backend->isLoaded()) {
            ModelEntry e;
            e.name = G.backend->loadedModelName();
            models.push_back(e);
        }
        sendSimple(req, 200, "application/json", adapter->listModelsJson(models));
        return;
    }

    if (method != "POST") {
        sendSimple(req, 405, "application/json", R"({"error":"method not allowed"})");
        return;
    }

    // POST = generate
    auto body = readBody(req);
    if (body.empty()) {
        sendSimple(req, 400, "application/json", R"({"error":"empty body"})");
        return;
    }

    if (!G.backend || !G.backend->isLoaded()) {
        sendSimple(req, 503, "application/json",
            R"({"error":"no model loaded. Start rawrxd-serve with --model <path>"})");
        return;
    }

    auto req2 = adapter->parseRequest(body);
    if (req2.model.empty()) req2.model = G.backend->loadedModelName();

    if (!req2.stream) {
        std::string full;
        G.backend->generate(req2, [&](const GenerationChunk& c) {
            full += c.token;
        });
        sendSimple(req, 200, "application/json",
                   adapter->buildFinalResponse(req2.model, full, req2));
        return;
    }

    // Streaming
    std::string preamble;
    if (adapter->name() == "anthropic") {
        preamble = adapter->buildStreamingChunk(req2.model, GenerationChunk{}, req2);
    }

    sendStreamStart(req, adapter->streamContentType(), preamble);

    std::string terminator = adapter->streamTerminator();
    bool sentTerminator = false;

    G.backend->generate(req2, [&](const GenerationChunk& c) {
        if (!terminator.empty() && c.done && !sentTerminator) {
            std::string s = adapter->buildStreamingChunk(req2.model, c, req2);
            sendStreamMore(req, s, false);
            sendStreamMore(req, terminator, true);
            sentTerminator = true;
        } else if (terminator.empty() && c.done) {
            std::string s = adapter->buildStreamingChunk(req2.model, c, req2);
            sendStreamMore(req, s, true);
        } else if (!c.token.empty()) {
            std::string s = adapter->buildStreamingChunk(req2.model, c, req2);
            sendStreamMore(req, s, false);
        }
    });
}

void listenerLoop() {
    std::vector<BYTE> buf(REQ_BUF_SIZE + sizeof(HTTP_REQUEST));
    auto* req = reinterpret_cast<HTTP_REQUEST*>(buf.data());

    while (G.running.load()) {
        std::memset(buf.data(), 0, buf.size());
        ULONG bytesReturned = 0;
        ULONG ret = HttpReceiveHttpRequest(
            G.reqQueue, HTTP_NULL_ID, 0, req,
            static_cast<ULONG>(buf.size()),
            &bytesReturned, nullptr);

        if (ret == NO_ERROR) {
            handleRequest(req);
        } else if (ret == ERROR_MORE_DATA) {
            buf.resize(bytesReturned + 1024);
            req = reinterpret_cast<HTTP_REQUEST*>(buf.data());
            ret = HttpReceiveHttpRequest(
                G.reqQueue, req->RequestId, 0, req,
                static_cast<ULONG>(buf.size()),
                &bytesReturned, nullptr);
            if (ret == NO_ERROR) handleRequest(req);
        } else if (ret == ERROR_OPERATION_ABORTED || ret == ERROR_CONNECTION_INVALID) {
            break;
        }
    }
}

bool initHttp() {
    HTTPAPI_VERSION ver = HTTPAPI_VERSION_2;
    ULONG ret = HttpInitialize(ver, HTTP_INITIALIZE_SERVER, nullptr);
    if (ret != NO_ERROR) { std::cerr << "HttpInitialize failed\n"; return false; }

    ret = HttpCreateServerSession(ver, &G.sessionId, 0);
    if (ret != NO_ERROR) { std::cerr << "HttpCreateServerSession failed\n"; return false; }

    ret = HttpCreateUrlGroup(G.sessionId, &G.urlGroupId, 0);
    if (ret != NO_ERROR) { std::cerr << "HttpCreateUrlGroup failed\n"; return false; }

    ret = HttpCreateRequestQueue(ver, L"RawrXDUniversalServe", nullptr, 0, &G.reqQueue);
    if (ret != NO_ERROR) { std::cerr << "HttpCreateRequestQueue failed\n"; return false; }

    HTTP_BINDING_INFO binding = {};
    binding.Flags.Present = 1;
    binding.RequestQueueHandle = G.reqQueue;
    ret = HttpSetUrlGroupProperty(G.urlGroupId, HttpServerBindingProperty,
                                  &binding, sizeof(binding));
    if (ret != NO_ERROR) { std::cerr << "binding failed\n"; return false; }

    std::wstring prefix = L"http://127.0.0.1:";
    prefix += std::to_wstring(G.port);
    prefix += L"/";

    ret = HttpAddUrlToUrlGroup(G.urlGroupId, prefix.c_str(), 0, 0);
    if (ret != NO_ERROR) {
        std::wcerr << L"HttpAddUrlToUrlGroup failed for " << prefix << L"\n";
        return false;
    }
    return true;
}

void shutdownHttp() {
    G.running = false;
    if (G.reqQueue) HttpShutdownRequestQueue(G.reqQueue);
    if (G.listener.joinable()) G.listener.join();
    if (G.urlGroupId)  HttpCloseUrlGroup(G.urlGroupId);
    if (G.sessionId)   HttpCloseServerSession(G.sessionId);
    if (G.reqQueue)    HttpCloseRequestQueue(G.reqQueue);
    HttpTerminate(HTTP_INITIALIZE_SERVER, nullptr);
}

} // anonymous namespace

int main(int argc, char** argv) {
    std::string modelPath;
    USHORT port = 8080;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--port" && i + 1 < argc) port = static_cast<USHORT>(std::stoi(argv[++i]));
        else if (a == "--model" && i + 1 < argc) modelPath = argv[++i];
        else if (a == "--help" || a == "-h") {
            std::cout <<
                "rawrxd-serve — Universal wire format LLM server\n"
                "Usage: rawrxd-serve --model <gguf-path> [--port 8080]\n"
                "Endpoints (no Ollama, no cloud):\n"
                "  POST /v1/chat/completions  (OpenAI)\n"
                "  POST /v1/completions       (OpenAI FIM)\n"
                "  GET  /v1/models            (OpenAI)\n"
                "  POST /v1/messages          (Anthropic)\n"
                "  GET  /health               (RawrXD-native)\n";
            return 0;
        }
    }

    G.port = port;

    RawrEngineBackend backend;
    if (!modelPath.empty()) {
        std::cout << "Loading model: " << modelPath << "\n";
        if (!backend.loadModel(modelPath)) {
            std::cerr << "Failed to load model\n";
            return 1;
        }
    } else {
        std::cout << "No --model given; server will return 503 until a model is loaded.\n";
    }
    G.backend = &backend;

    // Wire-format adapters — universal, no Ollama
    G.adapters.push_back(std::make_unique<OpenAIAdapter>());
    G.adapters.push_back(std::make_unique<AnthropicAdapter>());

    if (!initHttp()) return 1;

    G.running = true;
    G.listener = std::thread(listenerLoop);

    std::cout << "rawrxd-serve listening on http://127.0.0.1:" << port << "\n";
    std::cout << "Endpoints:\n";
    std::cout << "  POST /v1/chat/completions  (OpenAI)\n";
    std::cout << "  POST /v1/completions       (OpenAI FIM)\n";
    std::cout << "  GET  /v1/models            (OpenAI)\n";
    std::cout << "  POST /v1/messages          (Anthropic)\n";
    std::cout << "  GET  /health               (RawrXD)\n";
    std::cout << "Press Ctrl+C to stop.\n";

    std::signal(SIGINT, [](int){ G.running = false; });
    std::signal(SIGTERM, [](int){ G.running = false; });

    while (G.running.load()) std::this_thread::sleep_for(std::chrono::milliseconds(100));

    shutdownHttp();
    return 0;
}
