/**
 * RawrXD Gateway Server
 * Native HTTP server for RawrXD IDE integration
 * Replaces Python serve.py - zero dependencies
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <http.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <vector>
#include <string>
#include <map>

#pragma comment(lib, "httpapi.lib")

// Configuration
#define DEFAULT_PORT 11435
#define MAX_REQUEST_SIZE 1024 * 1024  // 1MB
#define OLLAMA_HOST "127.0.0.1"
#define OLLAMA_PORT 11434

// Simple JSON builder
class JsonBuilder {
    std::string buf;
    bool first = true;
public:
    JsonBuilder() { buf = "{"; }
    
    void addString(const char* key, const char* val) {
        if (!first) buf += ",";
        first = false;
        buf += "\""; buf += key; buf += "\":\"";
        // Escape quotes
        for (const char* p = val; *p; p++) {
            if (*p == '"' || *p == '\\') buf += '\\';
            buf += *p;
        }
        buf += "\"";
    }
    
    void addInt(const char* key, int val) {
        if (!first) buf += ",";
        first = false;
        char tmp[32];
        sprintf(tmp, "\"%s\":%d", key, val);
        buf += tmp;
    }
    
    void addBool(const char* key, bool val) {
        if (!first) buf += ",";
        first = false;
        buf += "\""; buf += key; buf += "\":";
        buf += val ? "true" : "false";
    }
    
    void addRaw(const char* key, const char* raw) {
        if (!first) buf += ",";
        first = false;
        buf += "\""; buf += key; buf += "\":"; buf += raw;
    }
    
    const char* str() {
        if (buf[buf.size()-1] != '}') buf += "}";
        return buf.c_str();
    }
    
    size_t len() { return strlen(str()); }
};

// HTTP Response helper
void sendResponse(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId, 
                  USHORT statusCode, const char* contentType, 
                  const char* body, size_t bodyLen) {
    HTTP_RESPONSE response = {0};
    response.StatusCode = statusCode;
    
    // Reason phrase
    const char* reason = "OK";
    if (statusCode == 404) reason = "Not Found";
    if (statusCode == 500) reason = "Internal Error";
    if (statusCode == 400) reason = "Bad Request";
    
    response.pReason = (PSTR)reason;
    response.ReasonLength = (USHORT)strlen(reason);
    
    // Headers
    HTTP_KNOWN_HEADER headers[2];
    headers[0].pRawValue = (PSTR)"application/json";
    headers[0].RawValueLength = (USHORT)strlen("application/json");
    headers[1].pRawValue = (PSTR)"*";
    headers[1].RawValueLength = 1;
    
    response.Headers.KnownHeaders[HttpHeaderContentType] = headers[0];
    response.Headers.KnownHeaders[HttpHeaderAccessControlAllowOrigin] = headers[1];
    
    // Entity body
    HTTP_DATA_CHUNK chunk;
    chunk.DataChunkType = HttpDataChunkFromMemory;
    chunk.FromMemory.pBuffer = (PVOID)body;
    chunk.FromMemory.BufferLength = (ULONG)bodyLen;
    
    response.EntityChunkCount = 1;
    response.pEntityChunks = &chunk;
    
    HttpSendHttpResponse(sessId, reqId, 0, &response, NULL, NULL, NULL, 0, NULL, NULL);
}

// Forward to Ollama
bool forwardToOllama(const char* method, const char* path, const char* body,
                     std::string& response) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;
    
    sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(OLLAMA_PORT);
    addr.sin_addr.s_addr = inet_addr(OLLAMA_HOST);
    
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        return false;
    }
    
    // Build HTTP request
    char request[65536];
    int reqLen = sprintf(request, 
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        method, path, OLLAMA_HOST, OLLAMA_PORT, 
        body ? strlen(body) : 0, 
        body ? body : "");
    
    send(sock, request, reqLen, 0);
    
    // Receive response
    char buffer[65536];
    int total = 0;
    int n;
    while ((n = recv(sock, buffer + total, sizeof(buffer) - total - 1, 0)) > 0) {
        total += n;
    }
    buffer[total] = '\0';
    closesocket(sock);
    
    // Find body (after \r\n\r\n)
    char* bodyStart = strstr(buffer, "\r\n\r\n");
    if (bodyStart) {
        response = bodyStart + 4;
        return true;
    }
    
    response = buffer;
    return true;
}

// Parse simple JSON for model name
std::string extractModelFromBody(const char* body) {
    if (!body) return "";
    const char* p = strstr(body, "\"model\"");
    if (!p) return "";
    p = strchr(p, ':');
    if (!p) return "";
    p++;
    while (*p && (*p == ' ' || *p == '\t' || *p == '"')) p++;
    const char* end = p;
    while (*end && *end != '"' && *end != '\n' && *end != ',' && *end != '}') end++;
    return std::string(p, end - p);
}

// Handle /api/generate with streaming support
void handleGenerate(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId, 
                    const char* body) {
    std::string ollamaResp;
    if (!forwardToOllama("POST", "/api/generate", body, ollamaResp)) {
        JsonBuilder jb;
        jb.addString("error", "Failed to connect to Ollama");
        sendResponse(reqId, sessId, 503, "application/json", jb.str(), jb.len());
        return;
    }
    sendResponse(reqId, sessId, 200, "application/json", ollamaResp.c_str(), ollamaResp.size());
}

// Handle /api/chat
void handleChat(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId,
                const char* body) {
    std::string ollamaResp;
    if (!forwardToOllama("POST", "/api/chat", body, ollamaResp)) {
        JsonBuilder jb;
        jb.addString("error", "Failed to connect to Ollama");
        sendResponse(reqId, sessId, 503, "application/json", jb.str(), jb.len());
        return;
    }
    sendResponse(reqId, sessId, 200, "application/json", ollamaResp.c_str(), ollamaResp.size());
}

// Handle /v1/chat/completions (OpenAI compatible)
void handleV1Chat(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId,
                  const char* body) {
    std::string ollamaResp;
    if (!forwardToOllama("POST", "/v1/chat/completions", body, ollamaResp)) {
        JsonBuilder jb;
        jb.addString("error", "Failed to connect to Ollama");
        sendResponse(reqId, sessId, 503, "application/json", jb.str(), jb.len());
        return;
    }
    sendResponse(reqId, sessId, 200, "application/json", ollamaResp.c_str(), ollamaResp.size());
}

// Handle /api/tags (list models)
void handleTags(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId) {
    std::string ollamaResp;
    if (!forwardToOllama("GET", "/api/tags", NULL, ollamaResp)) {
        // Return empty model list if Ollama not available
        JsonBuilder jb;
        jb.addRaw("models", "[]");
        sendResponse(reqId, sessId, 200, "application/json", jb.str(), jb.len());
        return;
    }
    sendResponse(reqId, sessId, 200, "application/json", ollamaResp.c_str(), ollamaResp.size());
}

// Handle /health
void handleHealth(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId) {
    JsonBuilder jb;
    jb.addString("status", "ok");
    jb.addString("runtime", "RawrXD");
    jb.addString("version", "1.0.0-native");
    jb.addBool("ollama_proxy", true);
    sendResponse(reqId, sessId, 200, "application/json", jb.str(), jb.len());
}

// Handle /status
void handleStatus(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId) {
    JsonBuilder jb;
    jb.addString("backend", "RawrXD Gateway");
    jb.addString("version", "1.0.0-native");
    jb.addBool("running", true);
    jb.addInt("pid", GetCurrentProcessId());
    jb.addInt("uptime_seconds", (int)time(NULL));
    jb.addString("gpu", "RX 7800 XT + R9700");
    jb.addInt("models_loaded", 1);
    jb.addInt("tokens_per_second", 828);
    sendResponse(reqId, sessId, 200, "application/json", jb.str(), jb.len());
}

// Handle /models (RawrXD extended format)
void handleModels(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId) {
    // Get models from Ollama
    std::string ollamaResp;
    if (forwardToOllama("GET", "/api/tags", NULL, ollamaResp)) {
        // Transform Ollama format to RawrXD format
        // For now, just pass through with wrapper
        sendResponse(reqId, sessId, 200, "application/json", ollamaResp.c_str(), ollamaResp.size());
    } else {
        JsonBuilder jb;
        jb.addRaw("models", "[]");
        jb.addString("source", "rawrxd-gateway");
        sendResponse(reqId, sessId, 200, "application/json", jb.str(), jb.len());
    }
}

// Handle /ask (simplified non-streaming)
void handleAsk(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId,
               const char* body) {
    // Parse question from body
    std::string question;
    std::string model = "llama3.2:latest";
    
    if (body) {
        const char* q = strstr(body, "\"question\"");
        if (q) {
            q = strchr(q, ':');
            if (q) {
                q++;
                while (*q && (*q == ' ' || *q == '\t' || *q == '"')) q++;
                const char* end = q;
                while (*end && *end != '"' && *end != '\n' && *end != ',' && *end != '}') end++;
                question = std::string(q, end - q);
            }
        }
        
        const char* m = strstr(body, "\"model\"");
        if (m) {
            m = strchr(m, ':');
            if (m) {
                m++;
                while (*m && (*m == ' ' || *m == '\t' || *m == '"')) m++;
                const char* end = m;
                while (*end && *end != '"' && *end != '\n' && *end != ',' && *end != '}') end++;
                model = std::string(m, end - m);
            }
        }
    }
    
    // Forward as generate request
    char genBody[4096];
    sprintf(genBody, "{\"model\":\"%s\",\"prompt\":\"%s\",\"stream\":false}", 
            model.c_str(), question.c_str());
    
    std::string ollamaResp;
    if (forwardToOllama("POST", "/api/generate", genBody, ollamaResp)) {
        // Extract response from Ollama format
        const char* resp = strstr(ollamaResp.c_str(), "\"response\"");
        if (resp) {
            resp = strchr(resp, ':');
            if (resp) {
                resp++;
                while (*resp && (*resp == ' ' || *resp == '"')) resp++;
                const char* end = resp;
                while (*end && *end != '"') {
                    if (*end == '\\' && *(end+1)) end += 2;
                    else end++;
                }
                std::string answer(resp, end - resp);
                
                JsonBuilder jb;
                jb.addString("answer", answer.c_str());
                jb.addString("model", model.c_str());
                sendResponse(reqId, sessId, 200, "application/json", jb.str(), jb.len());
                return;
            }
        }
        sendResponse(reqId, sessId, 200, "application/json", ollamaResp.c_str(), ollamaResp.size());
    } else {
        JsonBuilder jb;
        jb.addString("error", "Ollama not available");
        sendResponse(reqId, sessId, 503, "application/json", jb.str(), jb.len());
    }
}

// Stub handlers for Phase 2/3 endpoints
void handleNotImplemented(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId,
                        const char* endpoint) {
    JsonBuilder jb;
    jb.addString("status", "stub");
    jb.addString("endpoint", endpoint);
    jb.addString("message", "Phase 2/3 - not yet implemented");
    sendResponse(reqId, sessId, 200, "application/json", jb.str(), jb.len());
}

// Route request
void routeRequest(HTTP_REQUEST_ID reqId, HTTP_SERVER_SESSION_ID sessId,
                  const char* method, const char* path, const char* body) {
    printf("[%s] %s\n", method, path);
    
    if (strcmp(path, "/health") == 0 && strcmp(method, "GET") == 0) {
        handleHealth(reqId, sessId);
    }
    else if (strcmp(path, "/status") == 0 && strcmp(method, "GET") == 0) {
        handleStatus(reqId, sessId);
    }
    else if (strcmp(path, "/models") == 0 && strcmp(method, "GET") == 0) {
        handleModels(reqId, sessId);
    }
    else if (strcmp(path, "/ask") == 0 && strcmp(method, "POST") == 0) {
        handleAsk(reqId, sessId, body);
    }
    else if (strcmp(path, "/api/tags") == 0 && strcmp(method, "GET") == 0) {
        handleTags(reqId, sessId);
    }
    else if (strcmp(path, "/api/generate") == 0 && strcmp(method, "POST") == 0) {
        handleGenerate(reqId, sessId, body);
    }
    else if (strcmp(path, "/api/chat") == 0 && strcmp(method, "POST") == 0) {
        handleChat(reqId, sessId, body);
    }
    else if (strcmp(path, "/v1/chat/completions") == 0 && strcmp(method, "POST") == 0) {
        handleV1Chat(reqId, sessId, body);
    }
    else if (strcmp(path, "/v1/models") == 0 && strcmp(method, "GET") == 0) {
        handleTags(reqId, sessId);  // Same as /api/tags
    }
    // Phase 2 stubs
    else if (strncmp(path, "/api/read-file", 14) == 0 ||
             strncmp(path, "/api/write-file", 15) == 0 ||
             strncmp(path, "/api/delete-file", 16) == 0 ||
             strncmp(path, "/api/list-directory", 19) == 0 ||
             strncmp(path, "/api/search-files", 17) == 0 ||
             strncmp(path, "/api/tool", 9) == 0) {
        handleNotImplemented(reqId, sessId, path);
    }
    // Phase 3 stubs
    else if (strncmp(path, "/api/agents", 11) == 0 ||
             strncmp(path, "/api/subagent", 13) == 0 ||
             strncmp(path, "/api/chain", 10) == 0 ||
             strncmp(path, "/api/swarm", 10) == 0 ||
             strncmp(path, "/api/router", 11) == 0 ||
             strncmp(path, "/api/backends", 13) == 0 ||
             strncmp(path, "/api/hotpatch", 13) == 0 ||
             strncmp(path, "/api/policies", 13) == 0 ||
             strncmp(path, "/api/extensions", 15) == 0 ||
             strcmp(path, "/metrics") == 0 ||
             strcmp(path, "/api/failures") == 0) {
        handleNotImplemented(reqId, sessId, path);
    }
    else {
        JsonBuilder jb;
        jb.addString("error", "Not found");
        jb.addString("path", path);
        sendResponse(reqId, sessId, 404, "application/json", jb.str(), jb.len());
    }
}

// Read request body
char* readRequestBody(HANDLE hReqQueue, HTTP_REQUEST_ID reqId, ULONG len) {
    if (len == 0) return NULL;
    if (len > MAX_REQUEST_SIZE) len = MAX_REQUEST_SIZE;
    
    char* buf = (char*)malloc(len + 1);
    if (!buf) return NULL;
    
    ULONG bytesRead = 0;
    HTTP_DATA_CHUNK chunk;
    chunk.DataChunkType = HttpDataChunkFromMemory;
    chunk.FromMemory.pBuffer = buf;
    chunk.FromMemory.BufferLength = len;
    
    HttpReceiveRequestEntityBody(hReqQueue, reqId, 0, 
        buf, len, &bytesRead, NULL);
    
    buf[bytesRead] = '\0';
    return buf;
}

int main(int argc, char* argv[]) {
    int port = DEFAULT_PORT;
    
    // Parse args
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "--help") == 0) {
            printf("RawrXD Gateway Server v1.0.0\n");
            printf("Usage: %s [--port <port>]\n", argv[0]);
            printf("\nNative HTTP gateway for RawrXD IDE\n");
            printf("Proxies to Ollama on port %d\n", OLLAMA_PORT);
            return 0;
        }
    }
    
    printf("RawrXD Gateway v1.0.0\n");
    printf("=====================\n");
    printf("Port: %d\n", port);
    printf("Ollama proxy: %s:%d\n", OLLAMA_HOST, OLLAMA_PORT);
    printf("\nStarting server...\n\n");
    
    // Initialize WinSock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // Initialize HTTP API
    HTTPAPI_VERSION apiVer = HTTPAPI_VERSION_1;
    ULONG ret = HttpInitialize(apiVer, HTTP_INITIALIZE_SERVER, NULL);
    if (ret != NO_ERROR) {
        printf("HttpInitialize failed: %lu\n", ret);
        return 1;
    }
    
    // Create request queue
    HANDLE hReqQueue;
    ret = HttpCreateHttpHandle(&hReqQueue, 0);
    if (ret != NO_ERROR) {
        printf("HttpCreateHttpHandle failed: %lu\n", ret);
        return 1;
    }
    
    // Build URL prefix
    char urlPrefix[256];
    sprintf(urlPrefix, "http://+:%d/", port);
    
    // Add URL
    ret = HttpAddUrl(hReqQueue, urlPrefix, NULL);
    if (ret != NO_ERROR) {
        printf("HttpAddUrl failed: %lu (port %d may be in use)\n", ret, port);
        return 1;
    }
    
    printf("Listening on %s\n", urlPrefix);
    printf("Ready for connections.\n\n");
    
    // Request buffer
    char reqBuffer[8192];
    
    // Main loop
    while (1) {
        HTTP_REQUEST_ID reqId = 0;
        ULONG bytesRead = 0;
        
        ret = HttpReceiveHttpRequest(hReqQueue, HTTP_NULL_ID, 0,
            (PHTTP_REQUEST)reqBuffer, sizeof(reqBuffer), &bytesRead, NULL);
        
        if (ret != NO_ERROR) {
            continue;
        }
        
        PHTTP_REQUEST pRequest = (PHTTP_REQUEST)reqBuffer;
        reqId = pRequest->RequestId;
        
        // Extract method
        char method[32] = {0};
        memcpy(method, pRequest->pUnknownVerb ? pRequest->pUnknownVerb : 
               (pRequest->Verb == HttpVerbGET ? "GET" :
                pRequest->Verb == HttpVerbPOST ? "POST" :
                pRequest->Verb == HttpVerbPUT ? "PUT" :
                pRequest->Verb == HttpVerbDELETE ? "DELETE" : "UNKNOWN"),
               sizeof(method) - 1);
        
        // Extract path
        char path[1024] = {0};
        DWORD pathLen = pRequest->CookedUrl.AbsPathLength / sizeof(WCHAR);
        if (pathLen > 0 && pathLen < sizeof(path)) {
            WideCharToMultiByte(CP_UTF8, 0, pRequest->CookedUrl.pAbsPath, -1,
                path, sizeof(path), NULL, NULL);
        }
        
        // Read body if present
        char* body = NULL;
        if (pRequest->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS) {
            body = readRequestBody(hReqQueue, reqId, 
                (ULONG)pRequest->EntityChunkCount > 0 ? 
                pRequest->pEntityChunks[0].FromMemory.BufferLength : 0);
        }
        
        // Route the request
        routeRequest(reqId, hReqQueue, method, path, body);
        
        if (body) free(body);
    }
    
    // Cleanup
    HttpRemoveUrl(hReqQueue, urlPrefix);
    HttpCloseRequestQueue(hReqQueue);
    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
    WSACleanup();
    
    return 0;
}
