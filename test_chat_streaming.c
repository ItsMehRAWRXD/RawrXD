// ============================================================================
// test_chat_streaming.c
// Chat API streaming test for deepseek-r1:8b via Ollama
// Compile: gcc -O2 test_chat_streaming.c -o test_chat_streaming.exe -lwinhttp
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")

#define BUFFER_SIZE 8192

int main(void) {
    printf("========================================\n");
    printf("DeepSeek-R1:8b Chat Streaming Test\n");
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
    
    // Create request - use /api/chat instead of /api/generate
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/chat",
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    
    if (!hRequest) {
        printf("Failed to create request\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    // JSON payload for chat streaming
    const char* json_payload = "{"
        "\"model\":\"deepseek-r1:8b\","
        "\"messages\":[{\"role\":\"user\",\"content\":\"Say hello and count to 3\"}],"
        "\"stream\":true,"
        "\"options\":{\"temperature\":0.7}"
        "}";
    
    printf("Sending chat request to deepseek-r1:8b...\n");
    printf("Message: 'Say hello and count to 3'\n\n");
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
    DWORD total_tokens = 0;
    DWORD total_bytes = 0;
    clock_t start_time = clock();
    
    char read_buffer[BUFFER_SIZE];
    DWORD bytes_read = 0;
    char accumulated[BUFFER_SIZE * 4] = {0};
    size_t acc_len = 0;
    
    while (WinHttpReadData(hRequest, read_buffer, sizeof(read_buffer) - 1, &bytes_read) && bytes_read > 0) {
        read_buffer[bytes_read] = '\0';
        total_bytes += bytes_read;
        
        // Append to accumulated buffer
        if (acc_len + bytes_read < sizeof(accumulated) - 1) {
            memcpy(accumulated + acc_len, read_buffer, bytes_read);
            acc_len += bytes_read;
            accumulated[acc_len] = '\0';
        }
        
        // Process SSE events - look for data: lines
        char* p = accumulated;
        char* line_end;
        
        while ((line_end = strstr(p, "\n")) != NULL) {
            *line_end = '\0';
            
            // Check for data: lines
            if (strncmp(p, "data: ", 6) == 0) {
                const char* json_data = p + 6;
                
                // Check for [DONE]
                if (strstr(json_data, "[DONE]") != NULL) {
                    printf("\n[Stream ended with [DONE]]\n");
                    break;
                }
                
                // Look for "content":" in the message
                const char* content_key = "\"content\":\"";
                const char* content_start = strstr(json_data, content_key);
                if (content_start) {
                    content_start += strlen(content_key);
                    const char* content_end = content_start;
                    
                    // Find closing quote
                    while (*content_end && !(*content_end == '"' && *(content_end-1) != '\\')) {
                        content_end++;
                    }
                    
                    size_t content_len = content_end - content_start;
                    if (content_len > 0) {
                        // Print content (handle escapes simply)
                        for (size_t i = 0; i < content_len; i++) {
                            if (content_start[i] == '\\' && i + 1 < content_len) {
                                i++;
                                switch (content_start[i]) {
                                    case 'n': putchar('\n'); break;
                                    case 'r': putchar('\r'); break;
                                    case 't': putchar('\t'); break;
                                    case '\\': putchar('\\'); break;
                                    case '"': putchar('"'); break;
                                    default: putchar(content_start[i]); break;
                                }
                            } else {
                                putchar(content_start[i]);
                            }
                        }
                        fflush(stdout);
                        total_tokens++;
                    }
                }
                
                // Check if done=true
                if (strstr(json_data, "\"done\":true") != NULL) {
                    printf("\n[Stream ended with done=true]\n");
                    break;
                }
            }
            
            p = line_end + 1;
        }
        
        // Keep remaining partial data
        size_t remaining = acc_len - (p - accumulated);
        if (remaining > 0 && p > accumulated) {
            memmove(accumulated, p, remaining);
            acc_len = remaining;
            accumulated[acc_len] = '\0';
        } else {
            acc_len = 0;
            accumulated[0] = '\0';
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
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    printf("\n========================================\n");
    printf("Streaming test completed!\n");
    printf("========================================\n");
    
    return 0;
}
