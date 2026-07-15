// ============================================================================
// benchmark_streaming.c
// Performance benchmark for model streaming
// Compile: gcc -O2 benchmark_streaming.c -o benchmark_streaming.exe -lwinhttp
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")

#define MAX_SAMPLES 1000

typedef struct {
    double timestamp_ms;
    double latency_ms;
    size_t bytes_received;
    int token_count;
} Sample;

typedef struct {
    Sample samples[MAX_SAMPLES];
    int count;
    double start_time;
    double total_bytes;
    int total_tokens;
} Benchmark;

void benchmark_init(Benchmark* b) {
    memset(b, 0, sizeof(Benchmark));
    b->start_time = (double)clock() / CLOCKS_PER_SEC * 1000.0;
}

void benchmark_add_sample(Benchmark* b, double latency_ms, size_t bytes, int tokens) {
    if (b->count < MAX_SAMPLES) {
        b->samples[b->count].timestamp_ms = (double)clock() / CLOCKS_PER_SEC * 1000.0 - b->start_time;
        b->samples[b->count].latency_ms = latency_ms;
        b->samples[b->count].bytes_received = bytes;
        b->samples[b->count].token_count = tokens;
        b->count++;
    }
    b->total_bytes += bytes;
    b->total_tokens += tokens;
}

void benchmark_print_stats(Benchmark* b) {
    if (b->count == 0) {
        printf("No samples collected\n");
        return;
    }
    
    // Calculate statistics
    double total_time = b->samples[b->count - 1].timestamp_ms;
    double avg_latency = 0;
    double min_latency = b->samples[0].latency_ms;
    double max_latency = b->samples[0].latency_ms;
    
    for (int i = 0; i < b->count; i++) {
        avg_latency += b->samples[i].latency_ms;
        if (b->samples[i].latency_ms < min_latency) min_latency = b->samples[i].latency_ms;
        if (b->samples[i].latency_ms > max_latency) max_latency = b->samples[i].latency_ms;
    }
    avg_latency /= b->count;
    
    // Calculate standard deviation
    double variance = 0;
    for (int i = 0; i < b->count; i++) {
        double diff = b->samples[i].latency_ms - avg_latency;
        variance += diff * diff;
    }
    variance /= b->count;
    double std_dev = sqrt(variance);
    
    // Calculate percentiles
    double p50 = b->samples[b->count / 2].latency_ms;
    double p95 = b->samples[(int)(b->count * 0.95)].latency_ms;
    double p99 = b->samples[(int)(b->count * 0.99)].latency_ms;
    
    printf("\n");
    printf("========================================\n");
    printf("Streaming Performance Benchmark\n");
    printf("========================================\n");
    printf("Total Time:      %.2f ms\n", total_time);
    printf("Total Tokens:    %d\n", b->total_tokens);
    printf("Total Bytes:     %.2f KB\n", b->total_bytes / 1024.0);
    printf("Samples:         %d\n", b->count);
    printf("\n");
    printf("Throughput:\n");
    printf("  Tokens/sec:    %.2f\n", b->total_tokens * 1000.0 / total_time);
    printf("  KB/sec:        %.2f\n", (b->total_bytes / 1024.0) * 1000.0 / total_time);
    printf("\n");
    printf("Latency (ms):\n");
    printf("  Min:           %.2f\n", min_latency);
    printf("  Max:           %.2f\n", max_latency);
    printf("  Avg:           %.2f\n", avg_latency);
    printf("  Std Dev:       %.2f\n", std_dev);
    printf("  P50:           %.2f\n", p50);
    printf("  P95:           %.2f\n", p95);
    printf("  P99:           %.2f\n", p99);
    printf("========================================\n");
    
    // Performance rating
    double tps = b->total_tokens * 1000.0 / total_time;
    printf("\nPerformance Rating: ");
    if (tps >= 100) {
        printf("EXCELLENT (≥100 tps)\n");
    } else if (tps >= 50) {
        printf("GOOD (50-99 tps)\n");
    } else if (tps >= 20) {
        printf("ACCEPTABLE (20-49 tps)\n");
    } else {
        printf("NEEDS IMPROVEMENT (<20 tps)\n");
    }
}

int benchmark_streaming(const char* model, const char* prompt, int max_tokens) {
    printf("========================================\n");
    printf("Streaming Benchmark: %s\n", model);
    printf("========================================\n");
    printf("Prompt: %s\n", prompt);
    printf("Max Tokens: %d\n\n", max_tokens);
    
    Benchmark bench;
    benchmark_init(&bench);
    
    HINTERNET hSession = WinHttpOpen(L"RawrXD-Benchmark/1.0", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, 
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    if (!hSession) {
        printf("Failed to create WinHTTP session\n");
        return 1;
    }
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 11434, 0);
    if (!hConnect) {
        printf("Failed to connect to Ollama\n");
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate",
        NULL, WINHTTP_NO_REFERER, 
        WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    
    if (!hRequest) {
        printf("Failed to create request\n");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    // Build JSON payload
    char json_payload[1024];
    snprintf(json_payload, sizeof(json_payload),
        "{\"model\":\"%s\",\"prompt\":\"%s\",\"stream\":true,\"options\":{\"num_predict\":%d}}",
        model, prompt, max_tokens);
    
    printf("Starting benchmark...\n");
    
    if (!WinHttpSendRequest(hRequest,
            L"Content-Type: application/json\r\n",
            -1L,
            (LPVOID)json_payload, strlen(json_payload), strlen(json_payload), 0)) {
        printf("Failed to send request\n");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        printf("Failed to receive response\n");
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }
    
    // Read streaming response with timing
    char buffer[4096];
    DWORD bytesRead;
    clock_t last_token_time = clock();
    int first_token = 1;
    
    printf("Receiving tokens...\n");
    
    while (WinHttpReadData(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        
        clock_t now = clock();
        double latency_ms = ((double)(now - last_token_time)) / CLOCKS_PER_SEC * 1000.0;
        
        // Count tokens in this chunk
        int tokens = 0;
        char* p = buffer;
        while ((p = strstr(p, "data:")) != NULL) {
            p += 5;
            if (strstr(p, "\"content\":\"") || strstr(p, "\"response\":\"")) {
                tokens++;
            }
        }
        
        if (tokens > 0) {
            if (first_token) {
                printf("First token received (TTFT: %.2f ms)\n", latency_ms);
                first_token = 0;
            }
            benchmark_add_sample(&bench, latency_ms, bytesRead, tokens);
            last_token_time = now;
        }
    }
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    benchmark_print_stats(&bench);
    
    return 0;
}

int main(int argc, char* argv[]) {
    const char* model = (argc > 1) ? argv[1] : "deepseek-r1:8b";
    const char* prompt = (argc > 2) ? argv[2] : "Explain quantum computing in simple terms";
    int max_tokens = (argc > 3) ? atoi(argv[3]) : 50;
    
    return benchmark_streaming(model, prompt, max_tokens);
}
