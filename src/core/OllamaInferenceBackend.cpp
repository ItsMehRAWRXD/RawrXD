//==============================================================================
// OllamaInferenceBackend.cpp - HTTP backend for Ollama server
//
// This backend connects to an Ollama server via HTTP.
// Optional - for users who prefer Ollama over native inference.
//==============================================================================

#include "InferenceBackend.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

//==============================================================================
// Ollama Backend State
//==============================================================================

typedef struct OllamaBackendState {
    char endpoint[256];
    char model[128];
    int timeout_ms;
    int is_initialized;
} OllamaBackendState;

static OllamaBackendState g_ollama_state = {0};

//==============================================================================
// HTTP Client
//==============================================================================

static int HttpPost(const char* url, const char* json_body, 
                    char* response, size_t response_size, int timeout_ms) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    
    // Parse URL
    char host[256] = {0};
    char path[512] = {0};
    int port = 80;
    BOOL secure = FALSE;
    
    if (strncmp(url, "https://", 8) == 0) {
        secure = TRUE;
        port = 443;
        sscanf(url + 8, "%255[^/]/%511s", host, path);
    } else if (strncmp(url, "http://", 7) == 0) {
        sscanf(url + 7, "%255[^/]/%511s", host, path);
    } else {
        return -1;
    }
    
    // Create session
    hSession = WinHttpOpen(L"SovereignAgent/13.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return -1;
    
    // Set timeout
    WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
    
    // Connect
    wchar_t wHost[256];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 256);
    hConnect = WinHttpConnect(hSession, wHost, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return -1;
    }
    
    // Create request
    wchar_t wPath[512];
    MultiByteToWideChar(CP_UTF8, 0, path[0] ? path : "/", -1, wPath, 512);
    hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath, 
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }
    
    // Set headers
    WinHttpAddRequestHeaders(hRequest, 
        L"Content-Type: application/json\r\n",
        (ULONG)-1, WINHTTP_ADDREQ_FLAG_ADD);
    
    // Send request
    BOOL result = WinHttpSendRequest(hRequest, 
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)json_body, (DWORD)strlen(json_body),
        (DWORD)strlen(json_body), 0);
    
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }
    
    // Receive response
    result = WinHttpReceiveResponse(hRequest, NULL);
    if (!result) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return -1;
    }
    
    // Read response
    DWORD bytesRead = 0;
    size_t totalRead = 0;
    char buffer[4096];
    
    do {
        bytesRead = 0;
        if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead)) {
            break;
        }
        if (bytesRead > 0) {
            if (totalRead + bytesRead < response_size - 1) {
                memcpy(response + totalRead, buffer, bytesRead);
                totalRead += bytesRead;
            }
        }
    } while (bytesRead > 0);
    
    response[totalRead] = '\0';
    
    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return 0;
}

//==============================================================================
// Response Parsing
//==============================================================================

static int RejectReasoningTrace(const char* json_response, const char* content,
                                char* err, size_t err_size) {
    static const char* kBlockPrefixes[] = {
        "Here is", "Let's", "We will", "###", "**Given", "Step 1", "First,"
    };
    const char* key = "\"thinking\":\"";
    const char* t = strstr(json_response, key);
    if (t) {
        t += 13;
        if (*t != '\0' && *t != '"') {
            snprintf(err, err_size, "RAWRXD_NO_REASONING_EMIT_001: REASONING_FIELD nonempty");
            return -1;
        }
    }
    if (content && (strstr(content, "<think>") || strncmp(content, "Thinking:", 9) == 0)) {
        snprintf(err, err_size, "RAWRXD_NO_REASONING_EMIT_001: content think marker");
        return -1;
    }
    if (content) {
        for (size_t i = 0; i < sizeof(kBlockPrefixes) / sizeof(kBlockPrefixes[0]); ++i) {
            const size_t n = strlen(kBlockPrefixes[i]);
            if (strncmp(content, kBlockPrefixes[i], n) == 0) {
                snprintf(err, err_size, "RAWRXD_FINAL_ONLY_001: blocked prefix");
                return -1;
            }
        }
    }
    return 0;
}

static int ParseJsonIntField(const char* json, const char* field, int default_value) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\":", field);
    const char* start = strstr(json, pattern);
    if (!start) {
        return default_value;
    }
    start += strlen(pattern);
    while (*start == ' ') {
        ++start;
    }
    return atoi(start);
}

static size_t JsonEscape(const char* in, char* out, size_t out_size) {
    size_t o = 0;
    if (!in || !out || out_size == 0) {
        return 0;
    }
    for (; *in && (o + 2) < out_size; ++in) {
        const unsigned char c = static_cast<unsigned char>(*in);
        if (c == '"' || c == '\\') {
            if ((o + 3) >= out_size) break;
            out[o++] = '\\';
            out[o++] = static_cast<char>(c);
        } else if (c == '\n') {
            if ((o + 3) >= out_size) break;
            out[o++] = '\\';
            out[o++] = 'n';
        } else if (c != '\r') {
            out[o++] = static_cast<char>(c);
        }
    }
    out[o] = '\0';
    return o;
}

static void ExtractResponseContent(const char* json_response, 
                                   char* content, size_t content_size) {
    const char* key = "\"content\":\"";
    const char* start = strstr(json_response, key);
    if (!start) {
        key = "\"response\":\"";
        start = strstr(json_response, key);
        if (!start) {
            content[0] = '\0';
            return;
        }
    }
    
    start += strlen(key);
    const char* end = strstr(start, "\"");
    if (!end) {
        content[0] = '\0';
        return;
    }
    
    size_t len = end - start;
    if (len >= content_size) len = content_size - 1;
    
    strncpy(content, start, len);
    content[len] = '\0';
    
    // Unescape common sequences
    char* src = content;
    char* dst = content;
    while (*src) {
        if (*src == '\\' && *(src + 1)) {
            src++;
            switch (*src) {
                case 'n': *dst++ = '\n'; break;
                case 't': *dst++ = '\t'; break;
                case 'r': *dst++ = '\r'; break;
                case '\\': *dst++ = '\\'; break;
                case '"': *dst++ = '"'; break;
                default: *dst++ = *src; break;
            }
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

//==============================================================================
// Ollama Backend Implementation
//==============================================================================

static int Ollama_Initialize(const AgentConfig* config) {
    if (g_ollama_state.is_initialized) {
        return 0;
    }
    
    if (config) {
        strncpy(g_ollama_state.endpoint, config->endpoint, sizeof(g_ollama_state.endpoint) - 1);
        strncpy(g_ollama_state.model, config->model, sizeof(g_ollama_state.model) - 1);
        g_ollama_state.timeout_ms = config->default_timeout_ms;
    } else {
        // Defaults
        strcpy(g_ollama_state.endpoint, "");
        strcpy(g_ollama_state.model, "codellama");
        g_ollama_state.timeout_ms = 120000;
    }
    
    g_ollama_state.is_initialized = 1;
    printf("[OllamaBackend] Initialized. Endpoint: %s, Model: %s\n",
           g_ollama_state.endpoint, g_ollama_state.model);
    
    return 0;
}

static int Ollama_Shutdown(void) {
    g_ollama_state.is_initialized = 0;
    return 0;
}

static int Ollama_IsReady(void) {
    return g_ollama_state.is_initialized;
}

static int Ollama_LoadModel(const char* model_path) {
    // Ollama loads models via API, not file path
    // We just store the model name
    if (model_path) {
        strncpy(g_ollama_state.model, model_path, sizeof(g_ollama_state.model) - 1);
    }
    return 0;
}

static int Ollama_UnloadModel(void) {
    // Ollama keeps models loaded - nothing to do
    return 0;
}

static int Ollama_IsModelLoaded(void) {
    // Check if Ollama is reachable via HTTP health check
    if (!g_ollama_state.is_initialized) {
        return 0;
    }
    
    // Try to connect to Ollama API
    HINTERNET hSession = WinHttpOpen(L"RawrXD/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        return 0;
    }
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 0, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return 0;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/tags",
                                             nullptr, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 0;
    }
    
    // Set timeout
    WinHttpSetTimeouts(hRequest, 5000, 5000, 5000, 5000);
    
    // Send request
    BOOL result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                       WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    
    if (result) {
        result = WinHttpReceiveResponse(hRequest, nullptr);
    }
    
    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return result ? 1 : 0;
}

static int Ollama_Generate(const InferenceRequest* request, InferenceResult* result) {
    if (!g_ollama_state.is_initialized) {
        snprintf(result->error_message, sizeof(result->error_message),
                 "Ollama backend not initialized");
        return -1;
    }
    
    uint64_t start_time = GetTickCount64();
    const char* raw_prompt = request->prompt ? request->prompt : "";
    char escaped[AGENT_MAX_PROMPT * 2];
    JsonEscape(raw_prompt, escaped, sizeof(escaped));

    int npred = request->max_tokens > 0 ? request->max_tokens : 256;
    if (npred > 256) {
        npred = 256;
    }
    const float temp = request->temperature >= 0 ? request->temperature : 0.0f;

    char json_body[AGENT_MAX_PROMPT * 2];
    snprintf(json_body, sizeof(json_body),
        "{"
        "\"model\":\"%s\","
        "\"messages\":["
        "{\"role\":\"system\",\"content\":\"Return only the final answer. One line maximum. No explanation, derivation, headings, notes, caveats, restatement, or intermediate calculations.\"},"
        "{\"role\":\"user\",\"content\":\"%s\"}"
        "],"
        "\"think\":false,"
        "\"stream\":false,"
        "\"options\":{\"temperature\":%.2f,\"num_predict\":%d}"
        "}",
        g_ollama_state.model,
        escaped,
        temp,
        npred);

    char endpoint[512];
    snprintf(endpoint, sizeof(endpoint), "%s/api/chat", g_ollama_state.endpoint);
    
    char raw_response[AGENT_MAX_RESPONSE];
    int http_result = HttpPost(endpoint, json_body, raw_response, sizeof(raw_response),
                                g_ollama_state.timeout_ms);
    
    if (http_result != 0) {
        snprintf(result->error_message, sizeof(result->error_message),
                 "HTTP request failed - is Ollama running?");
        return -1;
    }
    
    ExtractResponseContent(raw_response, result->text, result->text_capacity);
    if (RejectReasoningTrace(raw_response, result->text, result->error_message, sizeof(result->error_message)) != 0) {
        result->success = 0;
        result->text_len = 0;
        if (result->text) {
            result->text[0] = '\0';
        }
        return -1;
    }
    result->text_len = strlen(result->text);
    result->duration_ms = GetTickCount64() - start_time;
    result->success = 1;

    const int eval_count = ParseJsonIntField(raw_response, "eval_count", -1);
    if (eval_count >= 0) {
        result->tokens_generated = eval_count;
    } else {
        result->tokens_generated = static_cast<int>(result->text_len / 4);
    }
    result->tokens_prompt = ParseJsonIntField(raw_response, "prompt_eval_count", static_cast<int>(strlen(request->prompt) / 4));
    const float dur_s = result->duration_ms > 0 ? (static_cast<float>(result->duration_ms) / 1000.0f) : 1.0f;
    result->tokens_per_second = static_cast<float>(result->tokens_generated) / dur_s;
    
    return 0;
}

static int Ollama_SupportsStreaming(void) {
    return 1;  // Ollama supports streaming
}

static int Ollama_SupportsBatching(void) {
    return 0;  // Not supported via this backend
}

static int Ollama_GetMaxContextLength(void) {
    return 8192;  // Depends on model, but typical for Ollama
}

static int Ollama_ClearContext(void) {
    // Ollama doesn't maintain context between requests by default
    return 0;
}

static int Ollama_SaveContext(const char* path) {
    (void)path;
    return -1;  // Not supported
}

static int Ollama_LoadContext(const char* path) {
    (void)path;
    return -1;  // Not supported
}

//==============================================================================
// Backend Factory
//==============================================================================

IInferenceBackend* OllamaBackend_Create(void) {
    IInferenceBackend* backend = (IInferenceBackend*)malloc(sizeof(IInferenceBackend));
    if (!backend) return nullptr;
    
    memset(backend, 0, sizeof(IInferenceBackend));
    
    backend->name = "ollama";
    backend->type = BACKEND_OLLAMA;
    
    backend->Initialize = Ollama_Initialize;
    backend->Shutdown = Ollama_Shutdown;
    backend->IsReady = Ollama_IsReady;
    
    backend->Generate = Ollama_Generate;
    
    backend->SupportsStreaming = Ollama_SupportsStreaming;
    backend->SupportsBatching = Ollama_SupportsBatching;
    backend->GetMaxContextLength = Ollama_GetMaxContextLength;
    
    backend->LoadModel = Ollama_LoadModel;
    backend->UnloadModel = Ollama_UnloadModel;
    backend->IsModelLoaded = Ollama_IsModelLoaded;
    
    backend->ClearContext = Ollama_ClearContext;
    backend->SaveContext = Ollama_SaveContext;
    backend->LoadContext = Ollama_LoadContext;
    
    return backend;
}
