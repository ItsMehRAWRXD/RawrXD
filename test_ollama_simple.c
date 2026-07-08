// ============================================================================
// test_ollama_simple.c
// Simple test for Ollama API
// Compile: gcc -O2 test_ollama_simple.c -o test_ollama_simple.exe -lwinhttp
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "winhttp.lib")

int main(void) {
    printf("Testing Ollama API...\n\n");
    
    // Initialize WinHTTP
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Test/1.0", 
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
    
    printf("Connected to Ollama\n");
    
    // Test 1: List models
    printf("\n[Test 1] Listing models...\n");
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/tags",
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    
    if (hRequest) {
        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                char buffer[4096];
                DWORD bytesRead;
                if (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead)) {
                    buffer[bytesRead] = '\0';
                    printf("Response (%lu bytes): %.200s...\n", bytesRead, buffer);
                }
            }
        }
        WinHttpCloseHandle(hRequest);
    }
    
    // Test 2: Generate with deepseek-r1:8b (non-streaming)
    printf("\n[Test 2] Generating with deepseek-r1:8b (non-streaming)...\n");
    hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate",
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    
    if (hRequest) {
        const char* json = "{\"model\":\"deepseek-r1:8b\",\"prompt\":\"Say hi\",\"stream\":false,\"options\":{\"num_predict\":10}}";
        
        printf("Sending: %s\n", json);
        
        if (WinHttpSendRequest(hRequest, 
                L"Content-Type: application/json\r\n",
                -1L,
                (LPVOID)json, strlen(json), strlen(json), 0)) {
            
            printf("Request sent, receiving response...\n");
            
            if (WinHttpReceiveResponse(hRequest, NULL)) {
                char buffer[8192];
                DWORD bytesRead;
                DWORD totalBytes = 0;
                
                while (WinHttpReadData(hRequest, buffer + totalBytes, 
                                       sizeof(buffer) - totalBytes - 1, &bytesRead) && bytesRead > 0) {
                    totalBytes += bytesRead;
                }
                
                if (totalBytes > 0) {
                    buffer[totalBytes] = '\0';
                    printf("Response (%lu bytes):\n%s\n", totalBytes, buffer);
                } else {
                    printf("No data received\n");
                }
            } else {
                printf("Failed to receive response (error: %lu)\n", GetLastError());
            }
        } else {
            printf("Failed to send request (error: %lu)\n", GetLastError());
        }
        
        WinHttpCloseHandle(hRequest);
    }
    
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    printf("\nTest complete!\n");
    return 0;
}
