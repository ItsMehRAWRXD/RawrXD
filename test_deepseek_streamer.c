// ============================================================================
// test_deepseek_streamer.c
// Simple test for streaming with deepseek-r1:8b via Ollama
// Compile: gcc -O2 test_deepseek_streamer.c -o test_deepseek_streamer.exe -lwinhttp
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")

#define OLLAMA_HOST L"localhost"
#define OLLAMA_PORT 11434
#define BUFFER_SIZE 4096

typedef struct {
    char* data;
    size_t size;
    size_t capacity;
} StringBuffer;

void sb_init(StringBuffer* sb) {
    sb->capacity = BUFFER_SIZE;
    sb->data = (char*)malloc(sb->capacity);
    sb->size = 0;
    sb->data[0] = '\0';
}

void sb_append(StringBuffer* sb, const char* str, size_t len) {
    if (sb->size + len + 1 > sb->capacity) {
        sb->capacity = (sb->size + len + 1) * 2;
        sb->data = (char*)realloc(sb->data, sb->capacity);
    }
    memcpy(sb->data + sb->size, str, len);
    sb->size += len;
    sb->data[sb->size] = '\0';
}

void sb_free(StringBuffer* sb) {
    free(sb->data);
    sb->data = NULL;
    sb->size = sb->capacity = 0;
}

// Extract content from JSON response
const char* extract_content(const char* json, size_t len) {
    static char content[4096];
    const char* content_key = "\"content\":\"";
    const char* start = strstr(json, content_key);
    if (!start) return NULL;
    
    start += strlen(content_key);
    const char* end = start;
    
    // Find closing quote (handle escaped quotes)
    while (*end && !(*end == '"' && *(end-1) != '\\')) {
        end++;
    }
    
    size_t content_len = end - start;
    if (content_len >= sizeof(content)) content_len = sizeof(content) - 1;
    
    memcpy(content, start, content_len);
    content[content_len] = '\0';
    
    return content;
}

// Unescape JSON string
void unescape_json(char* str) {
    char* src = str;
    char* dst = str;
    
    while (*src) {
        if (*src == '\\' && *(src+1)) {
            src++;
            switch (*src) {
                case 'n': *dst++ = '\n'; break;
                case 'r': *dst++ = '\r'; break;
                case 't': *dst++ = '\t'; break;
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

int test_streaming(void) {
    printf("========================================\n");
    printf("DeepSeek-R1:8b Streaming Test\n");
    printf("========================================\n\n");
    
    // Initialize WinHTTP
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Streamer/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        printf("Failed to create WinHTTP session\n");
        return 1;
    }
    
    // Connect to Ollama
    HINTERNET hConnect = WinHttpConnect(hSession, OLLAMA_HOST, OLLAMA_PORT, 0);
    if (!hConnect) {
        printf("Failed to connect to Ollama at localhost:11434\n");
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    printf("Connected to Ollama at localhost:11434\n\n");
    
    // Create request
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate",
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    
    if (!hRequest) {
        printf("Failed to create request\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    // JSON payload for streaming
    const char* json_payload = "{"
        "\"model\":\"deepseek-r1:8b\","
        "\"prompt\":\"Explain quantum computing in 3 sentences:\","
        "\"stream\":true,"
        "\"options\":{\"temperature\":0.7}"
        "}";
    
    printf("Sending request to deepseek-r1:8b...\n");
    printf("Prompt: 'Explain quantum computing in 3 sentences'\n\n");
    printf("--- Response Stream ---\n");
    
    // Send request
    BOOL result = WinHttpSendRequest(hRequest,
        L"Content-Type: application/json\r\n",
        -1L,
        (LPVOID)json_payload,
        strlen(json_payload),
        strlen(json_payload),
        0);
    
    if (!result) {
        printf("Failed to send request (error: %lu)\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    // Receive response
    result = WinHttpReceiveResponse(hRequest, NULL);
    if (!result) {
        printf("Failed to receive response (error: %lu)\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    // Read streaming response
    StringBuffer buffer;
    sb_init(&buffer);
    
    DWORD total_tokens = 0;
    DWORD total_bytes = 0;
    clock_t start_time = clock();
    
    char read_buffer[BUFFER_SIZE];
    DWORD bytes_read = 0;
    
    while (WinHttpReadData(hRequest, read_buffer, sizeof(read_buffer) - 1, &bytes_read) && bytes_read > 0) {
        read_buffer[bytes_read] = '\0';
        sb_append(&buffer, read_buffer, bytes_read);
        total_bytes += bytes_read;
        
        // Process SSE events
        char* line = strtok(buffer.data, "\n");
        while (line) {
            // Look for data: lines
            if (strncmp(line, "data: ", 6) == 0) {
                const char* json_data = line + 6;
                
                // Check for [DONE]
                if (strstr(json_data, "[DONE]") != NULL) {
                    break;
                }
                
                // Extract content
                const char* content = extract_content(json_data, strlen(json_data));
                if (content && strlen(content) > 0) {
                    char decoded[4096];
                    strncpy(decoded, content, sizeof(decoded) - 1);
                    decoded[sizeof(decoded) - 1] = '\0';
                    unescape_json(decoded);
                    printf("%s", decoded);
                    fflush(stdout);
                    total_tokens++;
                }
            }
            line = strtok(NULL, "\n");
        }
        
        // Reset buffer for next chunk
        buffer.size = 0;
        buffer.data[0] = '\0';
    }
    
    clock_t end_time = clock();
    double elapsed_ms = ((double)(end_time - start_time)) / CLOCKS_PER_SEC * 1000.0;
    
    printf("\n\n--- Stream Complete ---\n");
    printf("Total tokens: %lu\n", total_tokens);
    printf("Total bytes: %lu\n", total_bytes);
    printf("Time: %.2f ms\n", elapsed_ms);
    if (total_tokens > 0) {
        printf("Tokens/sec: %.2f\n", (total_tokens * 1000.0) / elapsed_ms);
        printf("ms/token: %.2f\n", elapsed_ms / total_tokens);
    }
    
    sb_free(&buffer);
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    printf("\n========================================\n");
    printf("Streaming test completed successfully!\n");
    printf("========================================\n");
    
    return 0;
}

int main(int argc, char* argv[]) {
    return test_streaming();
}
