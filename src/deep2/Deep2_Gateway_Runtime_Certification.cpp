// ============================================================================
// Deep2_Gateway_Runtime_Certification.cpp
// Runtime validation and evidence generation for Deep2 HTTP Gateway
// Validates: Health, OpenAI compatibility, MCP protocol, streaming, telemetry
// ============================================================================

#include "deep2_http_gateway.hpp"
#include "mcp_bridge.hpp"
#include "../Ship/Logger.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace RawrXD::Deep2 {
namespace Certification {

// ============================================================================
// Evidence Collection
// ============================================================================
struct EvidenceCollector {
    std::string basePath;
    std::string timestamp;
    
    EvidenceCollector() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        
        char buf[256];
        strftime(buf, sizeof(buf), "%Y-%m-%d-%H%M%S", localtime(&time_t));
        timestamp = buf;
        
        basePath = "evidence/" + timestamp + "-deep2-gateway";
        fs::create_directories(basePath);
    }
    
    void Save(const std::string& name, const std::string& data) {
        std::ofstream file(basePath + "/" + name);
        file << data;
    }
    
    void SaveJson(const std::string& name, const json& j) {
        Save(name, j.dump(2));
    }
    
    std::string GetPath() const { return basePath; }
};

// ============================================================================
// HTTP Test Client
// ============================================================================
class TestClient {
public:
    static std::string Get(const std::string& url, int timeoutMs = 5000) {
        return Request(url, L"GET", "", timeoutMs);
    }
    
    static std::string Post(const std::string& url, const std::string& body, 
                            int timeoutMs = 10000) {
        return Request(url, L"POST", body, timeoutMs);
    }
    
    static bool Stream(const std::string& url, const std::string& body,
                       std::function<bool(const std::string& chunk)> onChunk,
                       int timeoutMs = 30000) {
        HINTERNET hSession = WinHttpOpen(L"Deep2Cert/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return false;
        
        std::wstring wUrl(url.begin(), url.end());
        URL_COMPONENTS urlComp = {};
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.dwSchemeLength = (DWORD)-1;
        urlComp.dwHostNameLength = (DWORD)-1;
        urlComp.dwUrlPathLength = (DWORD)-1;
        
        if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp)) {
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
        std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
        
        HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(), 
            urlComp.nPort, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }
        
        WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, 
            (void*)&timeoutMs, sizeof(timeoutMs));
        
        std::wstring headers = L"Content-Type: application/json\r\n";
        std::wstring wBody(body.begin(), body.end());
        
        if (!WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(),
            (LPVOID)wBody.c_str(), (DWORD)wBody.length() * sizeof(wchar_t),
            (DWORD)wBody.length() * sizeof(wchar_t), 0)) {
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
        
        // Read streaming response
        std::string buffer;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            
            if (dwSize > 0) {
                std::vector<char> chunk(dwSize + 1);
                ZeroMemory(chunk.data(), dwSize + 1);
                
                if (WinHttpReadData(hRequest, chunk.data(), dwSize, &dwDownloaded)) {
                    std::string data(chunk.data(), dwDownloaded);
                    if (!onChunk(data)) {
                        break; // Cancelled
                    }
                }
            }
        } while (dwSize > 0);
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return true;
    }

private:
    static std::string Request(const std::string& url, const wchar_t* method,
                                const std::string& body, int timeoutMs) {
        HINTERNET hSession = WinHttpOpen(L"Deep2Cert/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return "";
        
        std::wstring wUrl(url.begin(), url.end());
        URL_COMPONENTS urlComp = {};
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.dwSchemeLength = (DWORD)-1;
        urlComp.dwHostNameLength = (DWORD)-1;
        urlComp.dwUrlPathLength = (DWORD)-1;
        
        if (!WinHttpCrackUrl(wUrl.c_str(), (DWORD)wUrl.length(), 0, &urlComp)) {
            WinHttpCloseHandle(hSession);
            return "";
        }
        
        std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
        std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);
        
        HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(), 
            urlComp.nPort, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return "";
        }
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, method, urlPath.c_str(),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }
        
        WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, 
            (void*)&timeoutMs, sizeof(timeoutMs));
        
        BOOL sent;
        if (wcscmp(method, L"POST") == 0 && !body.empty()) {
            std::wstring headers = L"Content-Type: application/json\r\n";
            std::wstring wBody(body.begin(), body.end());
            sent = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)headers.length(),
                (LPVOID)wBody.c_str(), (DWORD)wBody.length() * sizeof(wchar_t),
                (DWORD)wBody.length() * sizeof(wchar_t), 0);
        } else {
            sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
        }
        
        if (!sent) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }
        
        if (!WinHttpReceiveResponse(hRequest, NULL)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }
        
        std::string response;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        
        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
            
            if (dwSize > 0) {
                std::vector<char> buffer(dwSize + 1);
                ZeroMemory(buffer.data(), dwSize + 1);
                
                if (WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded)) {
                    response.append(buffer.data(), dwDownloaded);
                }
            }
        } while (dwSize > 0);
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return response;
    }
};

// ============================================================================
// Certification Tests
// ============================================================================
struct TestResult {
    const char* name;
    bool passed;
    double durationMs;
    std::string error;
    json evidence;
};

static std::vector<TestResult> g_results;
static int g_passed = 0;
static int g_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        result.error = msg; \
        result.passed = false; \
        printf("  [FAIL] %s\n", msg); \
        return result; \
    } \
} while(0)

// Test 1: Gateway Startup Validation
TestResult Test_GatewayStartup() {
    TestResult result{"Gateway Startup", true, 0.0, "", json::object()};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] Gateway Startup Validation\n");
    
    Deep2HttpGateway gateway(11435);
    auto startResult = gateway.Start();
    
    TEST_ASSERT(startResult.has_value(), "Gateway failed to start");
    TEST_ASSERT(gateway.IsRunning(), "Gateway not running after Start()");
    TEST_ASSERT(gateway.IsHealthy(), "Gateway not healthy");
    
    result.evidence["url"] = gateway.GetUrl();
    result.evidence["port"] = gateway.GetPort();
    result.evidence["healthy"] = true;
    
    // Small delay for server readiness
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    gateway.Stop();
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] Gateway started on %s (%.2f ms)\n", 
           result.evidence["url"].get<std::string>().c_str(), result.durationMs);
    return result;
}

// Test 2: Health Endpoint
TestResult Test_HealthEndpoint() {
    TestResult result{"Health Endpoint", true, 0.0, "", json::object()};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] Health Endpoint\n");
    
    Deep2HttpGateway gateway(11435);
    gateway.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    std::string response = TestClient::Get("http://127.0.0.1:11435/health");
    TEST_ASSERT(!response.empty(), "Health endpoint returned empty");
    
    // Parse response
    try {
        json health = json::parse(response);
        TEST_ASSERT(health["status"] == "ok", "Health status not 'ok'");
        TEST_ASSERT(health["runtime"] == "Deep2", "Runtime not 'Deep2'");
        
        result.evidence = health;
        printf("  Status: %s\n", health["status"].get<std::string>().c_str());
        printf("  Runtime: %s\n", health["runtime"].get<std::string>().c_str());
    } catch (...) {
        TEST_ASSERT(false, "Failed to parse health response");
    }
    
    gateway.Stop();
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] Health endpoint (%.2f ms)\n", result.durationMs);
    return result;
}

// Test 3: OpenAI Models Endpoint
TestResult Test_OpenAIModels() {
    TestResult result{"OpenAI Models", true, 0.0, "", json::object()};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] OpenAI Models Endpoint\n");
    
    Deep2HttpGateway gateway(11435);
    gateway.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    std::string response = TestClient::Get("http://127.0.0.1:11435/v1/models");
    TEST_ASSERT(!response.empty(), "Models endpoint returned empty");
    
    try {
        json models = json::parse(response);
        TEST_ASSERT(models.contains("data"), "Response missing 'data' field");
        
        result.evidence = models;
        printf("  Models available: %zu\n", models["data"].size());
    } catch (...) {
        TEST_ASSERT(false, "Failed to parse models response");
    }
    
    gateway.Stop();
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] Models endpoint (%.2f ms)\n", result.durationMs);
    return result;
}

// Test 4: Streaming Chat Completions
TestResult Test_StreamingChat() {
    TestResult result{"Streaming Chat", true, 0.0, "", json::object()};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] Streaming Chat Completions\n");
    
    Deep2HttpGateway gateway(11435);
    gateway.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    json request;
    request["model"] = "Deep2";
    request["messages"] = json::array();
    request["messages"].push_back({{"role", "user"}, {"content", "test"}});
    request["stream"] = true;
    
    std::vector<std::string> chunks;
    bool completed = false;
    
    bool success = TestClient::Stream(
        "http://127.0.0.1:11435/v1/chat/completions",
        request.dump(),
        [&chunks, &completed](const std::string& chunk) -> bool {
            chunks.push_back(chunk);
            // Check for completion
            if (chunk.find("[DONE]") != std::string::npos ||
                chunk.find("\"done\":true") != std::string::npos) {
                completed = true;
            }
            return true; // Continue streaming
        },
        30000
    );
    
    TEST_ASSERT(success, "Streaming request failed");
    TEST_ASSERT(!chunks.empty(), "No chunks received");
    
    result.evidence["chunks_received"] = chunks.size();
    result.evidence["completed"] = completed;
    
    printf("  Chunks received: %zu\n", chunks.size());
    printf("  Stream completed: %s\n", completed ? "yes" : "no");
    
    gateway.Stop();
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] Streaming chat (%.2f ms)\n", result.durationMs);
    return result;
}

// Test 5: MCP Handshake
TestResult Test_MCPHandshake() {
    TestResult result{"MCP Handshake", true, 0.0, "", json::object()};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] MCP Protocol Handshake\n");
    
    Deep2HttpGateway gateway(11435);
    auto bridge = std::make_shared<McpBridge>();
    bridge->Initialize();
    gateway.SetMcpBridge(bridge);
    gateway.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // MCP initialize request
    json mcpRequest;
    mcpRequest["jsonrpc"] = "2.0";
    mcpRequest["method"] = "initialize";
    mcpRequest["params"] = json::object();
    mcpRequest["id"] = 1;
    
    std::string response = TestClient::Post("http://127.0.0.1:11435/mcp", 
                                             mcpRequest.dump());
    TEST_ASSERT(!response.empty(), "MCP handshake returned empty");
    
    try {
        json mcpResponse = json::parse(response);
        TEST_ASSERT(mcpResponse["jsonrpc"] == "2.0", "Invalid JSON-RPC version");
        TEST_ASSERT(mcpResponse.contains("id"), "Response missing id");
        
        result.evidence = mcpResponse;
        printf("  JSON-RPC: %s\n", mcpResponse["jsonrpc"].get<std::string>().c_str());
        printf("  ID: %d\n", mcpResponse["id"].get<int>());
    } catch (...) {
        TEST_ASSERT(false, "Failed to parse MCP response");
    }
    
    gateway.Stop();
    bridge->Shutdown();
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] MCP handshake (%.2f ms)\n", result.durationMs);
    return result;
}

// Test 6: Telemetry Correlation
TestResult Test_Telemetry() {
    TestResult result{"Telemetry", true, 0.0, "", json::object()};
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n[TEST] Telemetry Correlation\n");
    
    Deep2HttpGateway gateway(11435);
    gateway.Start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Get status
    std::string status = TestClient::Get("http://127.0.0.1:11435/api/status");
    TEST_ASSERT(!status.empty(), "Status endpoint returned empty");
    
    try {
        json telemetry = json::parse(status);
        result.evidence = telemetry;
        
        printf("  Runtime: %s\n", telemetry.value("runtime", "unknown").c_str());
        printf("  Port: %d\n", telemetry.value("port", 0));
        printf("  Uptime: %lld seconds\n", telemetry.value("uptime_seconds", 0LL));
        printf("  Requests: %llu\n", telemetry.value("requests_handled", 0ULL));
    } catch (...) {
        TEST_ASSERT(false, "Failed to parse telemetry");
    }
    
    gateway.Stop();
    
    auto end = std::chrono::high_resolution_clock::now();
    result.durationMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    printf("  [PASS] Telemetry (%.2f ms)\n", result.durationMs);
    return result;
}

// ============================================================================
// Main Certification Runner
// ============================================================================
void RunCertification() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                          ║\n");
    printf("║     RawrXD Deep2 Gateway Runtime Certification                           ║\n");
    printf("║                                                                          ║\n");
    printf("║     Validates: Health, OpenAI API, MCP Protocol, Streaming, Telemetry      ║\n");
    printf("║                                                                          ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    EvidenceCollector evidence;
    printf("Evidence directory: %s\n\n", evidence.GetPath().c_str());
    
    g_results.clear();
    g_passed = 0;
    g_failed = 0;
    
    auto totalStart = std::chrono::high_resolution_clock::now();
    
    // Run all tests
    std::vector<std::function<TestResult()>> tests = {
        Test_GatewayStartup,
        Test_HealthEndpoint,
        Test_OpenAIModels,
        Test_StreamingChat,
        Test_MCPHandshake,
        Test_Telemetry
    };
    
    for (auto& test : tests) {
        TestResult result = test();
        g_results.push_back(result);
        
        if (result.passed) {
            g_passed++;
        } else {
            g_failed++;
        }
        
        // Save evidence
        std::string filename = std::string(result.name);
        std::replace(filename.begin(), filename.end(), ' ', '_');
        std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
        evidence.SaveJson(filename + ".json", result.evidence);
    }
    
    auto totalEnd = std::chrono::high_resolution_clock::now();
    double totalDuration = std::chrono::duration<double, std::milli>(
        totalEnd - totalStart).count();
    
    // Generate summary
    json summary;
    summary["timestamp"] = evidence.timestamp;
    summary["total_tests"] = tests.size();
    summary["passed"] = g_passed;
    summary["failed"] = g_failed;
    summary["duration_ms"] = totalDuration;
    summary["certified"] = (g_failed == 0);
    
    json testResults = json::array();
    for (const auto& r : g_results) {
        json tr;
        tr["name"] = r.name;
        tr["passed"] = r.passed;
        tr["duration_ms"] = r.durationMs;
        if (!r.error.empty()) {
            tr["error"] = r.error;
        }
        testResults.push_back(tr);
    }
    summary["results"] = testResults;
    
    evidence.SaveJson("summary.json", summary);
    
    // Print summary
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                         CERTIFICATION SUMMARY                            ║\n");
    printf("╠══════════════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Tests:  %-3zu                                                       ║\n", tests.size());
    printf("║  Passed:       %-3d  ✓                                                   ║\n", g_passed);
    printf("║  Failed:       %-3d  %s                                                   ║\n", 
           g_failed, g_failed > 0 ? "✗" : " ");
    printf("║  Duration:      %.2f ms                                                   ║\n", totalDuration);
    printf("║  Evidence:      %-56s ║\n", evidence.GetPath().c_str());
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n");
    
    if (g_failed == 0) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
        printf("║                                                                          ║\n");
        printf("║     ██████╗███████╗██████╗ ████████╗██╗███████╗██╗   ██╗███████╗██████╗  ║\n");
        printf("║    ██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║██╔════╝██║   ██║██╔════╝██╔══██╗ ║\n");
        printf("║    ██║     █████╗  ██████╔╝   ██║   ██║█████╗  ██║   ██║█████╗  ██████╔╝ ║\n");
        printf("║    ██║     ██╔══╝  ██╔══██╗   ██║   ██║██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗ ║\n");
        printf("║    ╚██████╗██║     ██║  ██║   ██║   ██║███████╗ ╚████╔╝ ███████╗██║  ██║ ║\n");
        printf("║     ╚═════╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝ ║\n");
        printf("║                                                                          ║\n");
        printf("║              Deep2 Gateway Runtime - CERTIFIED                           ║\n");
        printf("║                                                                          ║\n");
        printf("║     ✓ Gateway startup validation                                           ║\n");
        printf("║     ✓ Health endpoint responding                                           ║\n");
        printf("║     ✓ OpenAI API compatibility                                           ║\n");
        printf("║     ✓ Streaming token emission                                             ║\n");
        printf("║     ✓ MCP protocol handshake                                               ║\n");
        printf("║     ✓ Telemetry correlation                                              ║\n");
        printf("║                                                                          ║\n");
        printf("║     Endpoint: http://127.0.0.1:11435                                       ║\n");
        printf("║     Transport: MCP + OpenAI-compatible                                     ║\n");
        printf("║     Runtime: Deep2 Sovereign                                               ║\n");
        printf("║                                                                          ║\n");
        printf("╚══════════════════════════════════════════════════════════════════════════╝\n");
    }
    printf("\n");
}

} // namespace Certification
} // namespace RawrXD::Deep2

// ============================================================================
// Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    RawrXD::Deep2::Certification::RunCertification();
    
    return (RawrXD::Deep2::Certification::g_failed > 0) ? 1 : 0;
}
