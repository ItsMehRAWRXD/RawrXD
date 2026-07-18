// RawrXD REST API v2 - OpenAI Compatible
// Phase 9 - Task 7: REST API v2

#include <windows.h>
#include <http.h>
#include <json.h>
#include <string.h>
#include <vector>
#include <map>

#pragma comment(lib, "httpapi.lib")

// OpenAI-compatible API endpoints
// POST /v1/chat/completions
// POST /v1/completions
// POST /v1/embeddings
// GET  /v1/models
// GET  /v1/models/{model}

// Request structures
struct ChatCompletionRequest {
    char model[128];
    std::vector<std::map<std::string, std::string>> messages;
    float temperature;
    float top_p;
    int max_tokens;
    int n;
    bool stream;
    char stop[256];
};

struct CompletionRequest {
    char model[128];
    char prompt[4096];
    char suffix[256];
    int max_tokens;
    float temperature;
    float top_p;
    int n;
    bool stream;
    char stop[256];
};

struct EmbeddingsRequest {
    char model[128];
    char input[4096];
    char encoding_format[32];
    int dimensions;
};

// Response structures
struct ChatCompletionResponse {
    char id[64];
    char object[32];
    int64_t created;
    char model[128];
    std::vector<std::map<std::string, std::string>> choices;
    std::map<std::string, int> usage;
};

struct ModelInfo {
    char id[128];
    char object[32];
    int64_t created;
    char owned_by[64];
    std::map<std::string, std::string> permission;
};

// REST API server
class RestApiV2Server {
private:
    HANDLE hRequestQueue;
    int port;
    bool running;
    HANDLE serverThread;
    
    // Authentication
    std::map<std::string, std::string> apiKeys;
    bool authRequired;
    
public:
    RestApiV2Server() : hRequestQueue(nullptr), port(0), running(false), 
                       serverThread(nullptr), authRequired(true) {}
    
    ~RestApiV2Server() {
        Shutdown();
    }
    
    bool Initialize(int serverPort) {
        port = serverPort;
        
        // Initialize HTTP API
        HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
        ULONG result = HttpInitialize(version, HTTP_INITIALIZE_SERVER, nullptr);
        if (result != NO_ERROR) {
            printf("HttpInitialize failed: %lu\n", result);
            return false;
        }
        
        // Create request queue
        result = HttpCreateHttpHandle(&hRequestQueue, 0);
        if (result != NO_ERROR) {
            printf("HttpCreateHttpHandle failed: %lu\n", result);
            HttpTerminate(HTTP_INITIALIZE_SERVER);
            return false;
        }
        
        // Add URL prefix
        wchar_t urlPrefix[256];
        swprintf_s(urlPrefix, L"http://+:%d/v1/", port);
        
        result = HttpAddUrl(hRequestQueue, urlPrefix, nullptr);
        if (result != NO_ERROR) {
            printf("HttpAddUrl failed: %lu\n", result);
            HttpCloseRequestQueue(hRequestQueue);
            HttpTerminate(HTTP_INITIALIZE_SERVER);
            return false;
        }
        
        printf("REST API v2 initialized on port %d\n", port);
        printf("Endpoints:\n");
        printf("  POST /v1/chat/completions\n");
        printf("  POST /v1/completions\n");
        printf("  POST /v1/embeddings\n");
        printf("  GET  /v1/models\n");
        
        return true;
    }
    
    void AddApiKey(const char* key, const char* user) {
        apiKeys[key] = user;
    }
    
    bool ValidateApiKey(const char* authHeader) {
        if (!authRequired) return true;
        
        // Parse "Bearer {key}"
        const char* bearerPrefix = "Bearer ";
        if (strncmp(authHeader, bearerPrefix, strlen(bearerPrefix)) != 0) {
            return false;
        }
        
        const char* key = authHeader + strlen(bearerPrefix);
        return apiKeys.find(key) != apiKeys.end();
    }
    
    bool Start() {
        running = true;
        
        serverThread = CreateThread(nullptr, 0, ServerThreadProc, this, 0, nullptr);
        if (!serverThread) {
            return false;
        }
        
        printf("REST API v2 server started\n");
        return true;
    }
    
    static DWORD WINAPI ServerThreadProc(LPVOID param) {
        RestApiV2Server* server = (RestApiV2Server*)param;
        server->ServerLoop();
        return 0;
    }
    
    void ServerLoop() {
        while (running) {
            HTTP_REQUEST_ID requestId = 0;
            HTTP_V2_REQUEST_FLAGS flags = HTTP_V2_REQUEST_FLAG_NONE;
            PHTTP_REQUEST request = nullptr;
            ULONG requestBufferSize = sizeof(HTTP_REQUEST) + 4096;
            
            request = (PHTTP_REQUEST)malloc(requestBufferSize);
            if (!request) continue;
            
            RtlZeroMemory(request, requestBufferSize);
            
            ULONG result = HttpReceiveHttpRequest(
                hRequestQueue,
                requestId,
                flags,
                request,
                requestBufferSize,
                nullptr,
                nullptr
            );
            
            if (result == NO_ERROR) {
                HandleRequest(request);
            }
            
            free(request);
        }
    }
    
    void HandleRequest(PHTTP_REQUEST request) {
        // Convert URL to char
        char urlPath[256];
        WideCharToMultiByte(CP_UTF8, 0, request->CookedUrl.pAbsPath, -1,
                           urlPath, sizeof(urlPath), nullptr, nullptr);
        
        // Get authorization header
        char authHeader[256] = {0};
        for (ULONG i = 0; i < request->Headers.UnknownHeaderCount; i++) {
            if (_wcsicmp(request->Headers.pUnknownHeaders[i].pName, L"Authorization") == 0) {
                WideCharToMultiByte(CP_UTF8, 0, 
                                   request->Headers.pUnknownHeaders[i].pRawValue, -1,
                                   authHeader, sizeof(authHeader), nullptr, nullptr);
                break;
            }
        }
        
        // Validate API key
        if (!ValidateApiKey(authHeader)) {
            SendErrorResponse(request->RequestId, 401, "Unauthorized");
            return;
        }
        
        // Route request
        if (strcmp(urlPath, "/v1/chat/completions") == 0) {
            HandleChatCompletion(request);
        } else if (strcmp(urlPath, "/v1/completions") == 0) {
            HandleCompletion(request);
        } else if (strcmp(urlPath, "/v1/embeddings") == 0) {
            HandleEmbeddings(request);
        } else if (strcmp(urlPath, "/v1/models") == 0) {
            HandleListModels(request);
        } else {
            SendErrorResponse(request->RequestId, 404, "Not Found");
        }
    }
    
    void HandleChatCompletion(PHTTP_REQUEST request) {
        // Read request body
        char requestBody[4096] = {0};
        ULONG bytesRead = 0;
        
        if (request->Flags & HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS) {
            HttpReceiveRequestEntityBody(hRequestQueue, request->RequestId,
                                         HTTP_RECEIVE_REQUEST_ENTITY_BODY_FLAG_NONE,
                                         requestBody, sizeof(requestBody) - 1,
                                         &bytesRead, nullptr);
        }
        
        // Parse JSON request (simplified)
        // In production, use proper JSON parser
        ChatCompletionRequest req;
        strcpy_s(req.model, "gpt-3.5-turbo");  // Default
        req.temperature = 0.7f;
        req.max_tokens = 256;
        req.stream = false;
        
        // Check for stream parameter
        if (strstr(requestBody, "\"stream\":true")) {
            req.stream = true;
        }
        
        // Generate response
        if (req.stream) {
            SendStreamingChatResponse(request->RequestId, req);
        } else {
            SendChatResponse(request->RequestId, req);
        }
    }
    
    void SendChatResponse(HTTP_REQUEST_ID requestId, const ChatCompletionRequest& req) {
        // Build JSON response
        char responseBody[4096];
        sprintf_s(responseBody,
            "{\n"
            "  \"id\": \"chatcmpl-123\",\n"
            "  \"object\": \"chat.completion\",\n"
            "  \"created\": %lld,\n"
            "  \"model\": \"%s\",\n"
            "  \"choices\": [\n"
            "    {\n"
            "      \"index\": 0,\n"
            "      \"message\": {\n"
            "        \"role\": \"assistant\",\n"
            "        \"content\": \"Hello! How can I help you today?\"\n"
            "      },\n"
            "      \"finish_reason\": \"stop\"\n"
            "    }\n"
            "  ],\n"
            "  \"usage\": {\n"
            "    \"prompt_tokens\": 9,\n"
            "    \"completion_tokens\": 12,\n"
            "    \"total_tokens\": 21\n"
            "  }\n"
            "}\n",
            time(nullptr), req.model);
        
        SendJsonResponse(requestId, 200, responseBody);
    }
    
    void SendStreamingChatResponse(HTTP_REQUEST_ID requestId, const ChatCompletionRequest& req) {
        // Send streaming response headers
        HTTP_RESPONSE response = {};
        response.StatusCode = 200;
        response.pReason = "OK";
        response.ReasonLength = (USHORT)strlen(response.pReason);
        
        // Set content-type for SSE
        HTTP_HEADER_ID contentTypeHeader = HttpHeaderContentType;
        HTTP_KNOWN_HEADER* header = &response.Headers.KnownHeaders[contentTypeHeader];
        header->pRawValue = "text/event-stream";
        header->RawValueLength = (USHORT)strlen(header->pRawValue);
        
        HttpSendHttpResponse(hRequestQueue, requestId, 0, &response, nullptr, nullptr, nullptr, 0, nullptr, nullptr);
        
        // Send streaming chunks
        const char* chunks[] = {
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"index\":0}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"index\":0}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"!\"},\"index\":0}]}\n\n",
            "data: [DONE]\n\n"
        };
        
        for (const char* chunk : chunks) {
            HTTP_DATA_CHUNK dataChunk;
            dataChunk.DataChunkType = HttpDataChunkFromMemory;
            dataChunk.FromMemory.pBuffer = (PVOID)chunk;
            dataChunk.FromMemory.BufferLength = (ULONG)strlen(chunk);
            
            HttpSendResponseEntityBody(hRequestQueue, requestId, 
                                       HTTP_SEND_RESPONSE_FLAG_MORE_DATA,
                                       1, &dataChunk, nullptr, nullptr, 0, nullptr, nullptr);
            
            Sleep(100); // Simulate streaming delay
        }
    }
    
    void HandleCompletion(PHTTP_REQUEST request) {
        // Similar to chat completion but with prompt/completion format
        SendJsonResponse(request->RequestId, 200, 
            "{\"id\":\"cmpl-123\",\"object\":\"text_completion\",\"created\":1234567890,"
            "\"model\":\"text-davinci-003\",\"choices\":[{\"text\":\"Hello world\","
            "\"index\":0,\"logprobs\":null,\"finish_reason\":\"stop\"}],"
            "\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":7,\"total_tokens\":12}}");
    }
    
    void HandleEmbeddings(PHTTP_REQUEST request) {
        SendJsonResponse(request->RequestId, 200,
            "{\"object\":\"list\",\"data\":[{\"object\":\"embedding\","
            "\"embedding\":[0.1,0.2,0.3],\"index\":0}],"
            "\"model\":\"text-embedding-ada-002\",\"usage\":{\"prompt_tokens\":8,\"total_tokens\":8}}");
    }
    
    void HandleListModels(PHTTP_REQUEST request) {
        SendJsonResponse(request->RequestId, 200,
            "{\"object\":\"list\",\"data\":[{\"id\":\"gpt-3.5-turbo\","
            "\"object\":\"model\",\"created\":1677610602,\"owned_by\":\"openai\"},"
            "{\"id\":\"gpt-4\",\"object\":\"model\",\"created\":1687882411,\"owned_by\":\"openai\"}]}");
    }
    
    void SendJsonResponse(HTTP_REQUEST_ID requestId, int statusCode, const char* body) {
        HTTP_RESPONSE response = {};
        response.StatusCode = (USHORT)statusCode;
        response.pReason = (statusCode == 200) ? "OK" : "Error";
        response.ReasonLength = (USHORT)strlen(response.pReason);
        
        // Set content-type
        HTTP_HEADER_ID contentTypeHeader = HttpHeaderContentType;
        HTTP_KNOWN_HEADER* header = &response.Headers.KnownHeaders[contentTypeHeader];
        header->pRawValue = "application/json";
        header->RawValueLength = (USHORT)strlen(header->pRawValue);
        
        // Set body
        HTTP_DATA_CHUNK dataChunk;
        dataChunk.DataChunkType = HttpDataChunkFromMemory;
        dataChunk.FromMemory.pBuffer = (PVOID)body;
        dataChunk.FromMemory.BufferLength = (ULONG)strlen(body);
        
        response.EntityChunkCount = 1;
        response.pEntityChunks = &dataChunk;
        
        HttpSendHttpResponse(hRequestQueue, requestId, 0, &response, nullptr, nullptr, nullptr, 0, nullptr, nullptr);
    }
    
    void SendErrorResponse(HTTP_REQUEST_ID requestId, int statusCode, const char* message) {
        char body[256];
        sprintf_s(body, "{\"error\":{\"message\":\"%s\",\"type\":\"api_error\",\"code\":%d}}",
                  message, statusCode);
        SendJsonResponse(requestId, statusCode, body);
    }
    
    void Shutdown() {
        running = false;
        
        if (serverThread) {
            WaitForSingleObject(serverThread, 5000);
            CloseHandle(serverThread);
            serverThread = nullptr;
        }
        
        if (hRequestQueue) {
            HttpCloseRequestQueue(hRequestQueue);
            HttpTerminate(HTTP_INITIALIZE_SERVER);
            hRequestQueue = nullptr;
        }
    }
};

// Global instance
static RestApiV2Server g_RestApiV2;

// C API
extern "C" {

bool RestApiV2_Init(int port) {
    return g_RestApiV2.Initialize(port);
}

bool RestApiV2_Start() {
    return g_RestApiV2.Start();
}

void RestApiV2_Stop() {
    g_RestApiV2.Shutdown();
}

void RestApiV2_AddApiKey(const char* key, const char* user) {
    g_RestApiV2.AddApiKey(key, user);
}

} // extern "C"
