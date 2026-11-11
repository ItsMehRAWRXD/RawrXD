// ============================================================================
// test_deepseek_streaming.c
// Streaming test for deepseek-r1:8b via Ollama
// Compile: gcc -O2 test_deepseek_streaming.c -o test_deepseek_streaming.exe -lwinhttp
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")

#define BUFFER_SIZE 8192

typedef struct {
    char* data;
    size_t size;
    size_t capacity;
} StringBuffer;

void sb_init(StringBuffer* sb) {
    sb->capacity = BUFFER_SIZE;
    sb->data = (char*)malloc(sb->capacity);
    sb->size = 0;
    if (sb->data) sb->data[0] = '\0';
}

void sb_append(StringBuffer* sb, const char* str, size_t len) {
    if (!sb->data) return;
    if (sb->size + len + 1 > sb->capacity) {
        sb->capacity = (sb->size + len + 1) * 2;
        sb->data = (char*)realloc(sb->data, sb->capacity);
    }
    if (sb->data) {
        memcpy(sb->data + sb->size, str, len);
        sb->size += len;
        sb->data[sb->size] = '\0';
    }
}

void sb_free(StringBuffer* sb) {
    free(sb->data);
    sb->data = NULL;
    sb->size = sb->capacity = 0;
}

// Extract content from JSON response
const char* extract_json_field(const char* json, const char* field, char* out, size_t out_size) {
    char key[256];
    snprintf(key, sizeof(key), "\"%s\":\"", field);
    
    const char* start = strstr(json, key);
    if (!start) return NULL;
    
    start += strlen(key);
    const char* end = start;
    
    // Find closing quote (handle escaped quotes)
    while (*end) {
        if (*end == '"' && *(end-1) != '\\') break;
        end++;
    }
    
    size_t len = end - start;
    if (len >= out_size) len = out_size - 1;
    
    memcpy(out, start, len);
    out[len] = '\0';
    
    return out;
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

int main(void) {
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
    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 11434, 0);
    if (!hConnect) {
        printf("Failed to connect to Ollama (error: %lu)\n", GetLastError());
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
        "\"prompt\":\"Explain quantum computing in 2 sentences:\","
        "\"stream\":true,"
        "\"options\":{\"temperature\":0.7,\"num_predict\":100}"
        "}";
    
    printf("Sending request to deepseek-r1:8b...\n");
    printf("Prompt: 'Explain quantum computing in 2 sentences'\n\n");
    printf("--- Response Stream ---\n");
    
    // Send request
    if (!WinHttpSendRequest(hRequest,
            L"Content-Type: application/json\r\n",
            -1L,
            (LPVOID)json_payload, strlen(json_payload), strlen(json_payload), 0)) {
        printf("Failed to send request (error: %lu)\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
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
        
        // Process SSE events - look for complete lines
        char* line_start = buffer.data;
        char* line_end;
        
        while ((line_end = strstr(line_start, "\n")) != NULL) {
            *line_end = '\0';
            
            // Check for data: lines
            if (strncmp(line_start, "data: ", 6) == 0) {
                const char* json_data = line_start + 6;
                
                // Check for [DONE]
                if (strstr(json_data, "[DONE]") != NULL) {
                    break;
                }
                
                // Extract content
                char content[4096];
                if (extract_json_field(json_data, "content", content, sizeof(content))) {
                    if (strlen(content) > 0) {
                        unescape_json(content);
                        printf("%s", content);
                        fflush(stdout);
                        total_tokens++;
                    }
                }
                
                // Check if done
                char done_str[16];
                if (extract_json_field(json_data, "done", done_str, sizeof(done_str))) {
                    if (strcmp(done_str, "true") == 0) {
                        break;
                    }
                }
            }
            
            line_start = line_end + 1;
        }
        
        // Keep remaining partial line in buffer
        if (line_start > buffer.data) {
            size_t remaining = buffer.size - (line_start - buffer.data);
            memmove(buffer.data, line_start, remaining);
            buffer.size = remaining;
            buffer.data[buffer.size] = '\0';
        }
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
