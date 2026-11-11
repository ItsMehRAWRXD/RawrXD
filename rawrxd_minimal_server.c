// ============================================================================
// rawrxd_minimal_server.c - Minimal HTTP server for RawrXD
// Wraps sovereign_super_node.exe --inference as subprocess
// OpenAI-compatible API: /v1/completions, /v1/models, /health
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <process.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 8080
#define BUFFER_SIZE 8192
#define MAX_PATH_LEN 512

// Global configuration
char g_model_path[MAX_PATH_LEN] = "d:\\tinyllama_fresh.gguf";
int g_max_tokens = 50;

// ============================================================================
// HTTP Response Helpers
// ============================================================================
void send_http_response(SOCKET client, int status_code, const char* content_type, const char* body) {
    const char* status_text = (status_code == 200) ? "OK" : (status_code == 404) ? "Not Found" : "Error";
    char response[BUFFER_SIZE];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status_code, status_text, content_type, strlen(body), body);
    send(client, response, len, 0);
}

void send_json_response(SOCKET client, int status_code, const char* json) {
    send_http_response(client, status_code, "application/json", json);
}

// ============================================================================
// JSON Escape Helper
// ============================================================================
void json_escape(char* dst, size_t dst_size, const char* src) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        if (src[i] == '"' && j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = '"'; }
        else if (src[i] == '\\' && j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = '\\'; }
        else if (src[i] == '\n' && j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = 'n'; }
        else if (src[i] == '\r' && j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = 'r'; }
        else if (src[i] == '\t' && j < dst_size - 2) { dst[j++] = '\\'; dst[j++] = 't'; }
        else if ((unsigned char)src[i] < 0x20) { /* Skip control chars */ }
        else { dst[j++] = src[i]; }
    }
    dst[j] = '\0';
}

// ============================================================================
// Run Inference via sovereign_super_node.exe
// ============================================================================
int run_inference(const char* prompt, char* output, size_t output_size) {
    char cmdline[BUFFER_SIZE];
    char escaped_prompt[BUFFER_SIZE];
    
    // Escape quotes in prompt for command line
    size_t j = 0;
    for (size_t i = 0; prompt[i] && j < sizeof(escaped_prompt) - 2; i++) {
        if (prompt[i] == '"') {
            escaped_prompt[j++] = '\\';
            escaped_prompt[j++] = '\\';
            escaped_prompt[j++] = '"';
        } else {
            escaped_prompt[j++] = prompt[i];
        }
    }
    escaped_prompt[j] = '\0';
    
    // Build command: sovereign_super_node.exe --inference --model <path> --prompt "..." --max-tokens N
    snprintf(cmdline, sizeof(cmdline),
        "d:\\rawrxd\\build-ninja\\bin\\sovereign_super_node.exe --inference --model \"%s\" --prompt \"%s\" --max-tokens %d 2>nul",
        g_model_path, escaped_prompt, g_max_tokens);
    
    // Run subprocess and capture output
    FILE* pipe = _popen(cmdline, "r");
    if (!pipe) {
        strncpy(output, "Error: Failed to run inference", output_size);
        return -1;
    }
    
    // Read output
    size_t total = 0;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe) && total < output_size - 1) {
        size_t len = strlen(buffer);
        if (total + len < output_size - 1) {
            memcpy(output + total, buffer, len);
            total += len;
        }
    }
    output[total] = '\0';
    
    _pclose(pipe);
    return 0;
}

// ============================================================================
// Parse JSON for "prompt" field (simple parser)
// ============================================================================
const char* extract_json_string(const char* json, const char* key, char* value, size_t value_size) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* p = strstr(json, search);
    if (!p) return NULL;
    
    p += strlen(search);
    while (*p && (*p == ' ' || *p == ':' || *p == '\t')) p++;
    if (*p != '"') return NULL;
    p++;
    
    size_t i = 0;
    while (*p && *p != '"' && i < value_size - 1) {
        if (*p == '\\' && *(p+1)) {
            p++;
            switch (*p) {
                case 'n': value[i++] = '\n'; break;
                case 'r': value[i++] = '\r'; break;
                case 't': value[i++] = '\t'; break;
                case '"': value[i++] = '"'; break;
                case '\\': value[i++] = '\\'; break;
                default: value[i++] = *p; break;
            }
            p++;
        } else {
            value[i++] = *p++;
        }
    }
    value[i] = '\0';
    return value;
}

// ============================================================================
// HTTP Request Handlers
// ============================================================================
void handle_health(SOCKET client) {
    const char* json = "{\"status\":\"ok\",\"model\":\"tinyllama\",\"version\":\"1.0.0\"}";
    send_json_response(client, 200, json);
}

void handle_models(SOCKET client) {
    const char* json = "{\"object\":\"list\",\"data\":[{\"id\":\"tinyllama\",\"object\":\"model\",\"created\":1700000000,\"owned_by\":\"rawrxd\"}]}";
    send_json_response(client, 200, json);
}

void handle_completions(SOCKET client, const char* body) {
    char prompt[BUFFER_SIZE] = "";
    char max_tokens_str[32] = "50";
    
    // Extract prompt from JSON
    extract_json_string(body, "prompt", prompt, sizeof(prompt));
    extract_json_string(body, "max_tokens", max_tokens_str, sizeof(max_tokens_str));
    
    if (strlen(prompt) == 0) {
        send_json_response(client, 400, "{\"error\":\"Missing prompt\"}");
        return;
    }
    
    // Run inference
    char inference_output[BUFFER_SIZE * 2] = "";
    run_inference(prompt, inference_output, sizeof(inference_output));
    
    // Escape for JSON
    char escaped_output[BUFFER_SIZE * 4];
    json_escape(escaped_output, sizeof(escaped_output), inference_output);
    
    // Build response
    char response[BUFFER_SIZE * 8];
    snprintf(response, sizeof(response),
        "{\"id\":\"cmpl-rawrxd\",\"object\":\"text_completion\",\"created\":%lu,"
        "\"model\":\"tinyllama\",\"choices\":[{\"text\":\"%s\",\"index\":0,\"finish_reason\":\"stop\"}],"
        "\"usage\":{\"prompt_tokens\":%zu,\"completion_tokens\":%zu,\"total_tokens\":%zu}}",
        (unsigned long)time(NULL), escaped_output, strlen(prompt), strlen(inference_output), 
        strlen(prompt) + strlen(inference_output));
    
    send_json_response(client, 200, response);
}

// ============================================================================
// HTTP Request Parser
// ============================================================================
void handle_request(SOCKET client) {
    char buffer[BUFFER_SIZE];
    int received = recv(client, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) return;
    buffer[received] = '\0';
    
    // Parse request line
    char method[16] = "", path[256] = "";
    sscanf(buffer, "%15s %255s", method, path);
    
    // Find body (after \r\n\r\n)
    const char* body = strstr(buffer, "\r\n\r\n");
    if (body) body += 4;
    else body = "";
    
    printf("[%s] %s\n", method, path);
    
    // Route request
    if (strcmp(path, "/health") == 0) {
        handle_health(client);
    } else if (strcmp(path, "/v1/models") == 0) {
        handle_models(client);
    } else if (strcmp(path, "/v1/completions") == 0 && strcmp(method, "POST") == 0) {
        handle_completions(client, body);
    } else {
        send_http_response(client, 404, "text/plain", "Not Found");
    }
}

// ============================================================================
// Main Server Loop
// ============================================================================
int main(int argc, char* argv[]) {
    // Parse arguments
    int port = SERVER_PORT;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            strncpy(g_model_path, argv[++i], sizeof(g_model_path) - 1);
            g_model_path[sizeof(g_model_path) - 1] = '\0';
        } else if (strcmp(argv[i], "--max-tokens") == 0 && i + 1 < argc) {
            g_max_tokens = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("RawrXD Minimal HTTP Server\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --port <n>         Port to listen on (default: %d)\n", SERVER_PORT);
            printf("  --model <path>     Path to GGUF model\n");
            printf("  --max-tokens <n>   Max tokens per request (default: 50)\n");
            printf("  --help             Show this help\n");
            return 0;
        }
    }
    
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
    
    // Create socket
    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed\n");
        WSACleanup();
        return 1;
    }
    
    // Allow address reuse
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    
    // Bind
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed on port %d\n", port);
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Listen
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed\n");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("=================================================================\n");
    printf("  RawrXD Minimal HTTP Server\n");
    printf("  Listening on http://localhost:%d\n", port);
    printf("  Model: %s\n", g_model_path);
    printf("  Max tokens: %d\n", g_max_tokens);
    printf("=================================================================\n");
    printf("  Endpoints:\n");
    printf("    GET  /health         - Health check\n");
    printf("    GET  /v1/models      - List models\n");
    printf("    POST /v1/completions - Generate text\n");
    printf("=================================================================\n\n");
    
    // Accept connections
    while (1) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        SOCKET client = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        
        if (client == INVALID_SOCKET) continue;
        
        handle_request(client);
        closesocket(client);
    }
    
    // Cleanup
    closesocket(server_socket);
    WSACleanup();
    return 0;
}
