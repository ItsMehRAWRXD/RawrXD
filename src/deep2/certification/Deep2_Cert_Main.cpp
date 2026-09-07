// ============================================================================
// Deep2_Cert_Main.cpp - Standalone Gateway Runtime Certification
// Zero Ship dependencies. Zero C++23. Win32-native only.
// ============================================================================

#include <windows.h>
#include <winhttp.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

extern "C" int MockGatewayStart(unsigned short port);
extern "C" void MockGatewayStop();

// ============================================================================
// Minimal Types (No STL, No Ship)
// ============================================================================

struct CertResult {
    bool success;
    int  errorCode;
    char message[512];
    double durationMs;
};

struct TestEvidence {
    char name[64];
    char timestamp[32];
    char data[8192];
    bool passed;
};

// ============================================================================
// Minimal JSON Writer (No external deps)
// ============================================================================

void JsonBegin(char* buf, size_t bufSize, const char* objName) {
    _snprintf_s(buf, bufSize, _TRUNCATE, "{\n  \"test\": \"%s\",\n", objName);
}

void JsonAddString(char* buf, size_t bufSize, const char* key, const char* val) {
    size_t len = strlen(buf);
    _snprintf_s(buf + len, bufSize - len, _TRUNCATE, "  \"%s\": \"%s\",\n", key, val);
}

void JsonAddBool(char* buf, size_t bufSize, const char* key, bool val) {
    size_t len = strlen(buf);
    _snprintf_s(buf + len, bufSize - len, _TRUNCATE, "  \"%s\": %s,\n", key, val ? "true" : "false");
}

void JsonAddInt(char* buf, size_t bufSize, const char* key, int val) {
    size_t len = strlen(buf);
    _snprintf_s(buf + len, bufSize - len, _TRUNCATE, "  \"%s\": %d,\n", key, val);
}

void JsonAddDouble(char* buf, size_t bufSize, const char* key, double val) {
    size_t len = strlen(buf);
    _snprintf_s(buf + len, bufSize - len, _TRUNCATE, "  \"%s\": %.2f,\n", key, val);
}

void JsonEnd(char* buf, size_t bufSize) {
    size_t len = strlen(buf);
    // Remove trailing comma
    if (len > 2 && buf[len-2] == ',') {
        buf[len-2] = '\n';
        buf[len-1] = '\0';
        len--;
    }
    _snprintf_s(buf + len, bufSize - len, _TRUNCATE, "}\n");
}

// ============================================================================
// Evidence Collector
// ============================================================================

struct EvidenceCollector {
    char basePath[MAX_PATH];
    char timestamp[32];
    
    void Init() {
        // Create timestamp: YYYYMMDD-HHMMSS
        time_t now = time(NULL);
        struct tm tm;
        localtime_s(&tm, &now);
        strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &tm);
        
        // Create evidence directory under active workspace (not D:\RawrXD)
        _snprintf_s(basePath, sizeof(basePath), _TRUNCATE,
            "G:\\~dev\\rawrxd\\evidence\\deep2-gateway\\%s", timestamp);

        CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", NULL);
        CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\deep2-gateway", NULL);
        CreateDirectoryA(basePath, NULL);
    }
    
    void Save(const char* name, const char* data) {
        char path[MAX_PATH];
        _snprintf_s(path, sizeof(path), _TRUNCATE, "%s\\%s.json", basePath, name);
        
        FILE* fp = NULL;
        fopen_s(&fp, path, "w");
        if (fp) {
            fprintf(fp, "%s", data);
            fclose(fp);
        }
    }
    
    const char* GetPath() const { return basePath; }
};

// ============================================================================
// HTTP Test Client (WinHTTP, No external deps)
// ============================================================================

struct HttpClient {
    static int ParseUrl(const char* url, char* host, size_t hostN, int* port,
                        char* path, size_t pathN) {
        host[0] = path[0] = 0;
        *port = 80;
        const char* p = url;
        if (_strnicmp(p, "http://", 7) == 0) p += 7;
        const char* slash = strchr(p, '/');
        const char* colon = NULL;
        for (const char* q = p; q < (slash ? slash : p + strlen(p)); ++q)
            if (*q == ':') {
                colon = q;
                break;
            }
        if (colon) {
            size_t hn = (size_t)(colon - p);
            if (hn >= hostN) hn = hostN - 1;
            memcpy(host, p, hn);
            host[hn] = 0;
            *port = atoi(colon + 1);
        } else {
            size_t hn = slash ? (size_t)(slash - p) : strlen(p);
            if (hn >= hostN) hn = hostN - 1;
            memcpy(host, p, hn);
            host[hn] = 0;
        }
        if (slash)
            strncpy_s(path, pathN, slash, _TRUNCATE);
        else
            strncpy_s(path, pathN, "/", _TRUNCATE);
        return host[0] != 0;
    }

    static bool HttpGet(const char* url, char* response, size_t responseSize, int timeoutMs = 5000) {
        HINTERNET hSession = WinHttpOpen(L"Deep2Cert/1.0", 
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;
        
        char host[256] = {0};
        char path[512] = {0};
        int port = 80;
        if (!ParseUrl(url, host, sizeof(host), &port, path, sizeof(path))) {
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        wchar_t wHost[256];
        MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 256);
        
        HINTERNET hConnect = WinHttpConnect(hSession, wHost, (INTERNET_PORT)port, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        wchar_t wPath[512];
        MultiByteToWideChar(CP_UTF8, 0, path, -1, wPath, 512);
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath, 
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, (void*)&timeoutMs, sizeof(timeoutMs));
        
        if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, 
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        // Read response
        response[0] = '\0';
        DWORD totalRead = 0;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            
            if (dwSize > 0) {
                char* buffer = (char*)malloc(dwSize + 1);
                if (buffer) {
                    if (WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded)) {
                        buffer[dwDownloaded] = '\0';
                        if (totalRead + dwDownloaded < responseSize - 1) {
                            strcat_s(response, responseSize, buffer);
                            totalRead += dwDownloaded;
                        }
                    }
                    free(buffer);
                }
            }
        } while (dwSize > 0);
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return totalRead > 0;
    }
    
    static bool HttpPost(const char* url, const char* body, char* response, size_t responseSize, int timeoutMs = 10000) {
        (void)timeoutMs;
        // Raw Winsock POST — WinHTTP POST to loopback was unreliable in this island.
        char host[256] = {0};
        char path[512] = {0};
        int port = 80;
        if (!ParseUrl(url, host, sizeof(host), &port, path, sizeof(path))) return false;

        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons((u_short)port);
        inet_pton(AF_INET, host, &addr.sin_addr);
        if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
            closesocket(s);
            WSACleanup();
            return false;
        }
        char req[16384];
        int blen = (int)strlen(body);
        _snprintf_s(req, sizeof(req), _TRUNCATE,
                    "POST %s HTTP/1.1\r\nHost: %s:%d\r\nContent-Type: application/json\r\n"
                    "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
                    path, host, port, blen, body);
        if (send(s, req, (int)strlen(req), 0) <= 0) {
            closesocket(s);
            WSACleanup();
            return false;
        }
        response[0] = 0;
        int total = 0;
        char buf[2048];
        for (;;) {
            int n = recv(s, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;
            buf[n] = 0;
            if ((size_t)total + (size_t)n >= responseSize - 1) break;
            memcpy(response + total, buf, (size_t)n);
            total += n;
            response[total] = 0;
        }
        closesocket(s);
        WSACleanup();
        // Strip HTTP headers → body
        char* bodyStart = strstr(response, "\r\n\r\n");
        if (bodyStart) {
            bodyStart += 4;
            memmove(response, bodyStart, strlen(bodyStart) + 1);
        }
        return response[0] != 0;
    }
};

// ============================================================================
// Certification Tests
// ============================================================================

CertResult Test_HealthEndpoint(EvidenceCollector& evidence) {
    CertResult result = {true, 0, "", 0.0};
    clock_t start = clock();
    
    printf("\n[TEST] Health Endpoint\n");
    
    char response[4096] = {0};
    if (!HttpClient::HttpGet("http://127.0.0.1:11435/health", response, sizeof(response))) {
        result.success = false;
        result.errorCode = 1;
        strcpy_s(result.message, "Health endpoint request failed");
        printf("  [FAIL] %s\n", result.message);
        return result;
    }
    
    // Simple validation - check for "status" and "ok"
    if (!strstr(response, "status") || !strstr(response, "ok")) {
        result.success = false;
        result.errorCode = 2;
        strcpy_s(result.message, "Health response missing expected fields");
        printf("  [FAIL] %s\n", result.message);
        return result;
    }
    
    // Build evidence
    char json[8192] = {0};
    JsonBegin(json, sizeof(json), "health_endpoint");
    JsonAddString(json, sizeof(json), "endpoint", "http://127.0.0.1:11435/health");
    JsonAddBool(json, sizeof(json), "reachable", true);
    JsonAddString(json, sizeof(json), "response_preview", response);
    JsonAddBool(json, sizeof(json), "status_ok", true);
    JsonEnd(json, sizeof(json));
    
    evidence.Save("health", json);
    
    clock_t end = clock();
    result.durationMs = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    
    printf("  [PASS] Health endpoint (%.2f ms)\n", result.durationMs);
    return result;
}

CertResult Test_ModelsEndpoint(EvidenceCollector& evidence) {
    CertResult result = {true, 0, "", 0.0};
    clock_t start = clock();
    
    printf("\n[TEST] OpenAI Models Endpoint\n");
    
    char response[4096] = {0};
    if (!HttpClient::HttpGet("http://127.0.0.1:11435/v1/models", response, sizeof(response))) {
        result.success = false;
        result.errorCode = 1;
        strcpy_s(result.message, "Models endpoint request failed");
        printf("  [FAIL] %s\n", result.message);
        return result;
    }
    
    // Simple validation - check for "data" field
    if (!strstr(response, "data")) {
        result.success = false;
        result.errorCode = 2;
        strcpy_s(result.message, "Models response missing 'data' field");
        printf("  [FAIL] %s\n", result.message);
        return result;
    }
    
    // Build evidence
    char json[8192] = {0};
    JsonBegin(json, sizeof(json), "models_endpoint");
    JsonAddString(json, sizeof(json), "endpoint", "http://127.0.0.1:11435/v1/models");
    JsonAddBool(json, sizeof(json), "reachable", true);
    JsonAddString(json, sizeof(json), "response_preview", response);
    JsonEnd(json, sizeof(json));
    
    evidence.Save("models", json);
    
    clock_t end = clock();
    result.durationMs = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    
    printf("  [PASS] Models endpoint (%.2f ms)\n", result.durationMs);
    return result;
}

CertResult Test_ChatEndpoint(EvidenceCollector& evidence) {
    CertResult result = {true, 0, "", 0.0};
    clock_t start = clock();
    
    printf("\n[TEST] Chat Completions Endpoint\n");
    
    const char* requestBody = "{\"model\":\"Deep2\",\"messages\":[{\"role\":\"user\",\"content\":\"test\"}]}";
    char response[8192] = {0};
    
    if (!HttpClient::HttpPost("http://127.0.0.1:11435/v1/chat/completions", requestBody, response, sizeof(response))) {
        result.success = false;
        result.errorCode = 1;
        strcpy_s(result.message, "Chat endpoint request failed");
        printf("  [FAIL] %s\n", result.message);
        return result;
    }
    
    // Simple validation
    if (!strstr(response, "choices") && !strstr(response, "content")) {
        result.success = false;
        result.errorCode = 2;
        strcpy_s(result.message, "Chat response missing expected fields");
        printf("  [FAIL] %s\n", result.message);
        return result;
    }
    
    // Build evidence
    char json[8192] = {0};
    JsonBegin(json, sizeof(json), "chat_endpoint");
    JsonAddString(json, sizeof(json), "endpoint", "http://127.0.0.1:11435/v1/chat/completions");
    JsonAddBool(json, sizeof(json), "reachable", true);
    JsonAddString(json, sizeof(json), "request", requestBody);
    JsonAddString(json, sizeof(json), "response_preview", response);
    JsonEnd(json, sizeof(json));
    
    evidence.Save("chat", json);
    
    clock_t end = clock();
    result.durationMs = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    
    printf("  [PASS] Chat endpoint (%.2f ms)\n", result.durationMs);
    return result;
}

CertResult Test_MCPHandshake(EvidenceCollector& evidence) {
    CertResult result = {true, 0, "", 0.0};
    clock_t start = clock();
    
    printf("\n[TEST] MCP Protocol Handshake\n");
    
    const char* requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{},\"id\":1}";
    char response[4096] = {0};
    
    if (!HttpClient::HttpPost("http://127.0.0.1:11435/mcp", requestBody, response, sizeof(response))) {
        result.success = false;
        result.errorCode = 1;
        strcpy_s(result.message, "MCP handshake request failed");
        printf("  [FAIL] %s\n", result.message);
        return result;
    }
    
    // Validate JSON-RPC response
    if (!strstr(response, "jsonrpc") || !strstr(response, "2.0")) {
        result.success = false;
        result.errorCode = 2;
        strcpy_s(result.message, "MCP response not valid JSON-RPC 2.0");
        printf("  [FAIL] %s\n", result.message);
        return result;
    }
    
    // Build evidence
    char json[8192] = {0};
    JsonBegin(json, sizeof(json), "mcp_handshake");
    JsonAddString(json, sizeof(json), "endpoint", "http://127.0.0.1:11435/mcp");
    JsonAddBool(json, sizeof(json), "handshake_success", true);
    JsonAddString(json, sizeof(json), "request", requestBody);
    JsonAddString(json, sizeof(json), "response", response);
    JsonEnd(json, sizeof(json));
    
    evidence.Save("mcp_handshake", json);
    
    clock_t end = clock();
    result.durationMs = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    
    printf("  [PASS] MCP handshake (%.2f ms)\n", result.durationMs);
    return result;
}

CertResult Test_TelemetryEndpoint(EvidenceCollector& evidence) {
    CertResult result = {true, 0, "", 0.0};
    clock_t start = clock();
    
    printf("\n[TEST] Telemetry Endpoint\n");
    
    char response[4096] = {0};
    if (!HttpClient::HttpGet("http://127.0.0.1:11435/api/status", response, sizeof(response))) {
        result.success = false;
        result.errorCode = 1;
        strcpy_s(result.message, "Telemetry endpoint request failed");
        printf("  [FAIL] %s\n", result.message);
        return result;
    }
    
    // Build evidence
    char json[8192] = {0};
    JsonBegin(json, sizeof(json), "telemetry");
    JsonAddString(json, sizeof(json), "endpoint", "http://127.0.0.1:11435/api/status");
    JsonAddBool(json, sizeof(json), "reachable", true);
    JsonAddString(json, sizeof(json), "response", response);
    JsonEnd(json, sizeof(json));
    
    evidence.Save("telemetry", json);
    
    clock_t end = clock();
    result.durationMs = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    
    printf("  [PASS] Telemetry endpoint (%.2f ms)\n", result.durationMs);
    return result;
}

// ============================================================================
// Main Certification Runner
// ============================================================================

int main(int argc, char* argv[]) {
    int selftest = 1; // default: mock island (no Ship gateway required)
    for (int i = 1; i < argc; ++i) {
        if (argv[i] && strcmp(argv[i], "--live") == 0) selftest = 0;
        if (argv[i] && strcmp(argv[i], "--selftest") == 0) selftest = 1;
    }

    printf("\n");
    printf("============================================================\n");
    printf("  RawrXD Deep2 Gateway Runtime Certification\n");
    printf("  Standalone island: Win32 + WinHTTP only (no Ship/C++23)\n");
    printf("  Mode: %s\n", selftest ? "SELFTEST (mock gateway)" : "LIVE :11435");
    printf("============================================================\n\n");

    if (selftest) {
        if (!MockGatewayStart(11435)) {
            printf("FAIL: mock gateway bind :11435\n");
            puts("DEEP2_GATEWAY_RUNTIME_CERTIFICATION=FAIL");
            return 2;
        }
        Sleep(100);
    }

    EvidenceCollector evidence;
    evidence.Init();

    printf("Evidence directory: %s\n\n", evidence.GetPath());

    int passed = 0;
    int failed = 0;
    double totalDuration = 0.0;

    CertResult tests[5];
    // Map local CertResult (bool) to seal counts
    tests[0] = Test_HealthEndpoint(evidence);
    tests[1] = Test_ModelsEndpoint(evidence);
    tests[2] = Test_ChatEndpoint(evidence);
    tests[3] = Test_MCPHandshake(evidence);
    tests[4] = Test_TelemetryEndpoint(evidence);

    for (int i = 0; i < 5; i++) {
        if (tests[i].success) passed++;
        else failed++;
        totalDuration += tests[i].durationMs;
    }

    char summary[16384] = {0};
    JsonBegin(summary, sizeof(summary), "certification_summary");
    JsonAddString(summary, sizeof(summary), "timestamp", evidence.timestamp);
    JsonAddInt(summary, sizeof(summary), "total_tests", 5);
    JsonAddInt(summary, sizeof(summary), "passed", passed);
    JsonAddInt(summary, sizeof(summary), "failed", failed);
    JsonAddDouble(summary, sizeof(summary), "duration_ms", totalDuration);
    JsonAddBool(summary, sizeof(summary), "certified", (failed == 0));
    JsonAddString(summary, sizeof(summary), "mode",
                  selftest ? "selftest" : "live");
    JsonAddString(summary, sizeof(summary), "evidence_path", evidence.GetPath());
    JsonEnd(summary, sizeof(summary));
    evidence.Save("summary", summary);

    printf("\nSUMMARY passed=%d failed=%d duration_ms=%.2f\n", passed, failed,
           totalDuration);
    printf("evidence=%s\n", evidence.GetPath());

    if (selftest) MockGatewayStop();

    if (failed == 0) {
        puts("DEEP2_GATEWAY_RUNTIME_CERTIFICATION=PASS");
        // Stable path seal copy
        CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\deep2-gateway", NULL);
        FILE* seal = NULL;
        fopen_s(&seal,
                "G:\\~dev\\rawrxd\\evidence\\deep2-gateway\\SEAL.txt", "w");
        if (seal) {
            fprintf(seal, "DEEP2_GATEWAY_RUNTIME_CERTIFICATION=PASS\n");
            fprintf(seal, "SHIP_HEADERS=0\n");
            fprintf(seal, "CPP23=0\n");
            fprintf(seal, "MODE=%s\n", selftest ? "selftest" : "live");
            fclose(seal);
        }
        return 0;
    }
    puts("DEEP2_GATEWAY_RUNTIME_CERTIFICATION=FAIL");
    return 1;
}
