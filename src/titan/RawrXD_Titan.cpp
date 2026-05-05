// ============================================================
// RAWRXD TITAN DLL — Ollama HTTP Proxy (WinHTTP)
// No llama.dll needed. Calls Ollama on 127.0.0.1:11434.
// Also exports RawrXD_* API for Win32IDE integration.
// ============================================================

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <stdint.h>

#pragma comment(lib, "winhttp.lib")

// === RAWRXD TYPE DEFINITIONS ===
typedef int32_t RAWRXD_STATUS;
typedef uint64_t RAWRXD_MODEL_HANDLE;
typedef uint64_t RAWRXD_INFERENCE_HANDLE;

#define RAWRXD_SUCCESS                    0x00000000
#define RAWRXD_ERROR_NOT_INITIALIZED      0x80000001
#define RAWRXD_ERROR_INVALID_PARAM        0x80000002
#define RAWRXD_ERROR_NOT_READY            0x80000003
#define RAWRXD_ERROR_NO_MODEL_LOADED      0x80000004

typedef struct {
    float temperature;
    float top_p;
    int32_t top_k;
    float repetition_penalty;
    int32_t max_tokens;
} RAWRXD_SAMPLING_PARAMS;

typedef struct {
    uint64_t output_buffer;
    uint32_t output_token_count;
    uint32_t input_token_count;
    uint64_t latency_ms;
    RAWRXD_STATUS status;
} RAWRXD_INFERENCE_RESULT;

#ifdef __cplusplus
extern "C" {
#endif

// === TITAN LEGACY EXPORTS ===
__declspec(dllexport) int  Titan_LoadModel(const char* model_path);
__declspec(dllexport) int  Titan_IsLoaded(void);
__declspec(dllexport) void Titan_UnloadModel(void);
__declspec(dllexport) int  Titan_PredictFIM(const char* prefix,
                                              const char* suffix,
                                              char* output,
                                              int output_max_len,
                                              int max_tokens,
                                              float temperature);
__declspec(dllexport) int  Titan_PredictChat(const char* prompt,
                                               char* output,
                                               int output_max_len,
                                               int max_tokens,
                                               float temperature);

// === RAWRXD API EXPORTS (what Win32IDE_GhostText.cpp expects) ===
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_Initialize(void);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_Shutdown(void);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_LoadModel(const char* model_path, RAWRXD_MODEL_HANDLE* model_handle);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_SelectModel(RAWRXD_MODEL_HANDLE model_handle);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_SetSamplingParams(const RAWRXD_SAMPLING_PARAMS* params);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_InferAsync(const char* prompt, RAWRXD_INFERENCE_HANDLE* handle);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_WaitForInference(RAWRXD_INFERENCE_HANDLE handle, uint32_t timeout_ms, RAWRXD_INFERENCE_RESULT* result);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_CancelInference(RAWRXD_INFERENCE_HANDLE handle);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_BeginStreaming(const char* prompt, RAWRXD_INFERENCE_HANDLE* handle);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_EndStreaming(RAWRXD_INFERENCE_HANDLE handle);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_StreamPop(RAWRXD_INFERENCE_HANDLE handle, char* token_buffer, size_t buffer_size, uint32_t* tokens_received);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_StreamConfigureWindow(uint32_t context_window, uint32_t overlap_tokens);
__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_StreamReset(RAWRXD_INFERENCE_HANDLE handle);

#ifdef __cplusplus
}
#endif

static bool  g_loaded = false;
static char  g_model_name[256] = {0};
static char  g_last_error[512] = {0};

static void safe_strcpy(char* dst, int dst_size, const char* src) {
    if (!dst || dst_size <= 0) return;
    if (!src) { dst[0] = '\0'; return; }
    int i = 0;
    while (i < dst_size - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = '\0';
}

static void set_error(const char* msg) {
    safe_strcpy(g_last_error, sizeof(g_last_error), msg);
    OutputDebugStringA("[Titan] ERROR: ");
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
}

static std::string http_post_json(const char* host, int port,
                                   const char* path,
                                   const std::string& json_body) {
    std::string response;
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Titan/1.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME,
                                      WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return response;

    HINTERNET hConnect = WinHttpConnect(hSession, L"127.0.0.1", (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return response; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate",
                                             NULL, WINHTTP_NO_REFERER,
                                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                                             WINHTTP_FLAG_ESCAPE_PERCENT);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return response; }

    std::wstring headers = L"Content-Type: application/json\r\n";
    BOOL sent = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(),
                                    (LPVOID)json_body.c_str(), (DWORD)json_body.length(),
                                    (DWORD)json_body.length(), 0);
    if (!sent || !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    DWORD dwSize = 0;
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        char* buf = (char*)malloc(dwSize + 1);
        if (!buf) break;
        DWORD dwRead = 0;
        WinHttpReadData(hRequest, buf, dwSize, &dwRead);
        buf[dwRead] = '\0';
        response += buf;
        free(buf);
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

static std::string extract_response_text(const std::string& json) {
    // Very simple JSON extraction: find "response":"..."
    size_t pos = json.find("\"response\"");
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + 10);
    if (pos == std::string::npos) return "";
    size_t end = json.find("\"", pos + 1);
    if (end == std::string::npos) return "";
    std::string raw = json.substr(pos + 1, end - pos - 1);
    // Unescape common sequences
    std::string result;
    for (size_t i = 0; i < raw.length(); i++) {
        if (raw[i] == '\\' && i + 1 < raw.length()) {
            switch (raw[i+1]) {
                case 'n': result += '\n'; i++; break;
                case 'r': result += '\r'; i++; break;
                case 't': result += '\t'; i++; break;
                case '\\': result += '\\'; i++; break;
                case '"': result += '"'; i++; break;
                default: result += raw[i+1]; i++; break;
            }
        } else {
            result += raw[i];
        }
    }
    return result;
}

static int ollama_generate(const char* prompt, char* output, int output_max_len,
                            int max_tokens, float temperature) {
    if (!prompt || !output || output_max_len <= 0) return -1;

    const char* model = g_model_name[0] ? g_model_name : "codestral";

    // Build JSON body
    std::string json = "{\"model\":\"";
    json += model;
    json += "\",\"prompt\":\"";
    // Escape prompt for JSON
    for (const char* p = prompt; *p; p++) {
        if (*p == '\\' || *p == '"') json += '\\';
        if (*p == '\n') { json += "\\n"; continue; }
        if (*p == '\r') { json += "\\r"; continue; }
        if (*p == '\t') { json += "\\t"; continue; }
        json += *p;
    }
    json += "\",\"stream\":false,\"options\":{\"num_predict\":";
    json += std::to_string(max_tokens);
    json += ",\"temperature\":";
    json += std::to_string(temperature);
    json += "}}";

    std::string resp = http_post_json("127.0.0.1", 11434, "/api/generate", json);
    if (resp.empty()) {
        safe_strcpy(output, output_max_len, "// Titan: Ollama unreachable on 127.0.0.1:11434");
        return -1;
    }

    std::string text = extract_response_text(resp);
    if (text.empty()) {
        safe_strcpy(output, output_max_len, "// Titan: empty response from Ollama");
        return -1;
    }

    safe_strcpy(output, output_max_len, text.c_str());
    return (int)text.length();
}

__declspec(dllexport) int Titan_LoadModel(const char* model_path) {
    if (!model_path || !model_path[0]) {
        set_error("Titan_LoadModel: null or empty model_path");
        return 0;
    }
    safe_strcpy(g_model_name, sizeof(g_model_name), model_path);
    g_loaded = true;
    OutputDebugStringA("[Titan] Model set to: ");
    OutputDebugStringA(g_model_name);
    OutputDebugStringA("\n");
    return 1;
}

__declspec(dllexport) int Titan_IsLoaded(void) {
    return g_loaded ? 1 : 0;
}

__declspec(dllexport) void Titan_UnloadModel(void) {
    g_loaded = false;
    g_model_name[0] = '\0';
}

__declspec(dllexport) int Titan_PredictFIM(const char* prefix,
                                              const char* suffix,
                                              char* output,
                                              int output_max_len,
                                              int max_tokens,
                                              float temperature) {
    if (!prefix) prefix = "";
    if (!suffix) suffix = "";

    // Build FIM prompt (Codestral format)
    std::string prompt = "[FIM_PROMPT]\n";
    prompt += prefix;
    prompt += "\n[SUFFIX]\n";
    prompt += suffix;
    prompt += "\n[MIDDLE]\n";

    return ollama_generate(prompt.c_str(), output, output_max_len,
                           max_tokens, temperature);
}

__declspec(dllexport) int Titan_PredictChat(const char* prompt,
                                               char* output,
                                               int output_max_len,
                                               int max_tokens,
                                               float temperature) {
    if (!prompt) prompt = "";
    return ollama_generate(prompt, output, output_max_len,
                           max_tokens, temperature);
}

// === TITAN LEGACY EXPORTS (what bridge_titan_4a.cpp expects) ===

__declspec(dllexport) int Titan_Initialize(const char* model_path) {
    OutputDebugStringA("[Titan] Titan_Initialize called with model: ");
    OutputDebugStringA(model_path ? model_path : "(null)");
    OutputDebugStringA("\n");
    if (!model_path || !model_path[0]) {
        set_error("Titan_Initialize: null or empty model_path");
        return -1;
    }
    safe_strcpy(g_model_name, sizeof(g_model_name), model_path);
    g_loaded = true;
    return 0;  // success
}

typedef struct {
    const char*  prompt;
    int          max_tokens;
    float        temperature;
    void       (*callback)(const char* text, int len);
} TITAN_INFERENCE_PARAMS;

__declspec(dllexport) int Titan_InferAsync(TITAN_INFERENCE_PARAMS* params) {
    if (!params || !params->prompt || !params->callback) {
        set_error("Titan_InferAsync: invalid params");
        return -1;
    }
    if (!g_loaded) {
        set_error("Titan_InferAsync: model not loaded");
        return -1;
    }

    char output[4096] = {0};
    int max_tokens = params->max_tokens > 0 ? params->max_tokens : 50;
    float temperature = params->temperature > 0 ? params->temperature : 0.7f;

    int result = ollama_generate(params->prompt, output, sizeof(output),
                                   max_tokens, temperature);
    if (result > 0 && params->callback) {
        params->callback(output, result);
    }
    return result;
}

__declspec(dllexport) void Titan_Shutdown(void) {
    OutputDebugStringA("[Titan] Titan_Shutdown called\n");
    Titan_UnloadModel();
}

// === RAWRXD API IMPLEMENTATION ===

static bool g_rawrxd_initialized = false;
static RAWRXD_MODEL_HANDLE g_active_model = 0;
static RAWRXD_SAMPLING_PARAMS g_sampling_params = {0.7f, 0.9f, 40, 1.0f, 256};

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_Initialize(void) {
    OutputDebugStringA("[Titan] RawrXD_Initialize called\n");
    g_rawrxd_initialized = true;
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_Shutdown(void) {
    OutputDebugStringA("[Titan] RawrXD_Shutdown called\n");
    g_rawrxd_initialized = false;
    g_active_model = 0;
    Titan_UnloadModel();
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_LoadModel(const char* model_path, RAWRXD_MODEL_HANDLE* model_handle) {
    OutputDebugStringA("[Titan] RawrXD_LoadModel called\n");
    if (!g_rawrxd_initialized) {
        return RAWRXD_ERROR_NOT_INITIALIZED;
    }
    if (!model_path || !model_handle) {
        return RAWRXD_ERROR_INVALID_PARAM;
    }
    if (!Titan_LoadModel(model_path)) {
        return RAWRXD_ERROR_NO_MODEL_LOADED;
    }
    g_active_model = 1;
    *model_handle = g_active_model;
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_SelectModel(RAWRXD_MODEL_HANDLE model_handle) {
    g_active_model = model_handle;
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_SetSamplingParams(const RAWRXD_SAMPLING_PARAMS* params) {
    if (!params) return RAWRXD_ERROR_INVALID_PARAM;
    g_sampling_params = *params;
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_InferAsync(const char* prompt, RAWRXD_INFERENCE_HANDLE* handle) {
    if (!g_rawrxd_initialized || !g_loaded) {
        return RAWRXD_ERROR_NOT_READY;
    }
    if (!prompt || !handle) {
        return RAWRXD_ERROR_INVALID_PARAM;
    }
    *handle = 1;
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_WaitForInference(RAWRXD_INFERENCE_HANDLE handle, uint32_t timeout_ms, RAWRXD_INFERENCE_RESULT* result) {
    if (!result) return RAWRXD_ERROR_INVALID_PARAM;
    memset(result, 0, sizeof(RAWRXD_INFERENCE_RESULT));
    result->status = RAWRXD_SUCCESS;
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_CancelInference(RAWRXD_INFERENCE_HANDLE handle) {
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_BeginStreaming(const char* prompt, RAWRXD_INFERENCE_HANDLE* handle) {
    return RawrXD_InferAsync(prompt, handle);
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_EndStreaming(RAWRXD_INFERENCE_HANDLE handle) {
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_StreamPop(RAWRXD_INFERENCE_HANDLE handle, char* token_buffer, size_t buffer_size, uint32_t* tokens_received) {
    if (!token_buffer || buffer_size == 0 || !tokens_received) {
        return RAWRXD_ERROR_INVALID_PARAM;
    }
    *tokens_received = 0;
    token_buffer[0] = '\0';
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_StreamConfigureWindow(uint32_t context_window, uint32_t overlap_tokens) {
    return RAWRXD_SUCCESS;
}

__declspec(dllexport) RAWRXD_STATUS __stdcall RawrXD_StreamReset(RAWRXD_INFERENCE_HANDLE handle) {
    return RAWRXD_SUCCESS;
}

// === DLL ENTRY POINT ===

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            Titan_UnloadModel();
    }
    return TRUE;
}
