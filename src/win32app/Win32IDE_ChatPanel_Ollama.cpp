// ============================================================================
// Win32IDE Chat Panel - Ollama Integration
// Implements model fetching and chat inference via Ollama REST API
// ============================================================================

#include "Win32IDE.h"
#include <windows.h>
#include <winhttp.h>
#include <thread>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

namespace {
    // Ollama API endpoints
    const char* OLLAMA_API_TAGS = "/api/tags";
    const char* OLLAMA_API_GENERATE = "/api/generate";
    const char* OLLAMA_API_CHAT = "/api/chat";
    
    // UTF-8 <-> Wide string conversion helpers
    static std::string wideToUtf8(const std::wstring& wide) {
        if (wide.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], size, nullptr, nullptr);
        return result;
    }
    
    static std::wstring utf8ToWide(const std::string& utf8) {
        if (utf8.empty()) return L"";
        int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
        std::wstring result(size - 1, 0);
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], size);
        return result;
    }
    
    // Helper to make HTTP request to Ollama
    std::string HttpRequest(const std::string& host, int port, 
                           const std::string& endpoint,
                           const std::string& method = "GET",
                           const std::string& body = "",
                           int timeoutMs = 30000)
    {
        std::string result;
        
        HINTERNET hSession = WinHttpOpen(L"RawrXD-IDE/1.0", 
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, 
            WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) return result;
        
        std::wstring wHost = std::wstring(host.begin(), host.end());
        HINTERNET hConnect = WinHttpConnect(hSession, wHost.c_str(), 
            static_cast<INTERNET_PORT>(port), 0);
        
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return result;
        }
        
        std::wstring wEndpoint = std::wstring(endpoint.begin(), endpoint.end());
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, 
            method == "POST" ? L"POST" : L"GET",
            wEndpoint.c_str(), 
            NULL, WINHTTP_NO_REFERER, 
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_REFRESH);
        
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return result;
        }
        
        // Set timeout
        WinHttpSetTimeouts(hRequest, timeoutMs, timeoutMs, timeoutMs, timeoutMs);
        
        // Add headers for POST
        if (method == "POST") {
            WinHttpAddRequestHeaders(hRequest, 
                L"Content-Type: application/json\r\n", 
                (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD);
        }
        
        // Send request
        BOOL bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            method == "POST" ? (LPVOID)body.c_str() : WINHTTP_NO_REQUEST_DATA,
            method == "POST" ? (DWORD)body.length() : 0,
            method == "POST" ? (DWORD)body.length() : 0, 0);
        
        if (bResults) {
            bResults = WinHttpReceiveResponse(hRequest, NULL);
        }
        
        if (bResults) {
            DWORD dwSize = 0;
            do {
                dwSize = 0;
                WinHttpQueryDataAvailable(hRequest, &dwSize);
                
                if (dwSize > 0) {
                    std::vector<char> buffer(dwSize + 1);
                    DWORD dwDownloaded = 0;
                    WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded);
                    buffer[dwDownloaded] = '\0';
                    result += buffer.data();
                }
            } while (dwSize > 0);
        }
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return result;
    }
}

// ============================================================================
// Fetch available models from Ollama
// ============================================================================
void Win32IDE::fetchOllamaModelsAsync()
{
    std::thread([this]() {
        std::string response = HttpRequest("localhost", 11434, OLLAMA_API_TAGS);
        
        if (response.empty()) {
            OutputDebugStringA("[Ollama] Failed to fetch models - is Ollama running?\n");
            return;
        }
        
        try {
            auto j = json::parse(response);
            std::vector<std::string> models;
            
            if (j.contains("models") && j["models"].is_array()) {
                for (const auto& model : j["models"]) {
                    if (model.contains("name")) {
                        models.push_back(model["name"]);
                    }
                }
            }
            
            // Update UI on main thread
            if (m_hwndMain) {
                PostMessage(m_hwndMain, WM_APP + 300, 
                    reinterpret_cast<WPARAM>(new std::vector<std::string>(models)), 0);
            }
        }
        catch (const std::exception& e) {
            char buf[256];
            snprintf(buf, sizeof(buf), "[Ollama] JSON parse error: %s\n", e.what());
            OutputDebugStringA(buf);
        }
    }).detach();
}

// ============================================================================
// Handle model list update message
// ============================================================================
void Win32IDE::onOllamaModelsUpdated(std::vector<std::string>* models)
{
    if (!models) return;
    
    // Store models
    m_availableModels = *models;
    delete models;
    
    // Update dropdown
    if (m_hwndModelSelector) {
        SendMessage(m_hwndModelSelector, CB_RESETCONTENT, 0, 0);
        
        for (const auto& model : m_availableModels) {
            SendMessageW(m_hwndModelSelector, CB_ADDSTRING, 0, 
                (LPARAM)std::wstring(model.begin(), model.end()).c_str());
        }
        
        if (!m_availableModels.empty()) {
            SendMessage(m_hwndModelSelector, CB_SETCURSEL, 0, 0);
        }
    }
    
    char buf[256];
    snprintf(buf, sizeof(buf), "[Ollama] Loaded %zu models\n", m_availableModels.size());
    OutputDebugStringA(buf);
}

// ============================================================================
// Send chat message to Ollama and stream response
// ============================================================================
void Win32IDE::sendChatMessageToOllama(const std::string& message, 
                                       std::function<void(const std::string&, bool)> callback)
{
    // Get selected model
    int modelIdx = (int)SendMessage(m_hwndModelSelector, CB_GETCURSEL, 0, 0);
    std::string modelName = "llama3.2:3b"; // default
    
    if (modelIdx >= 0 && modelIdx < (int)m_availableModels.size()) {
        modelName = m_availableModels[modelIdx];
    }
    
    // Get max tokens
    int maxTokens = m_currentMaxTokens;
    if (maxTokens < 32) maxTokens = 512;
    
    // Build request body
    json requestBody = {
        {"model", modelName},
        {"prompt", message},
        {"stream", true},
        {"options", {
            {"num_predict", maxTokens},
            {"temperature", 0.7}
        }}
    };
    
    std::string requestJson = requestBody.dump();
    
    // Launch async request
    std::thread([this, requestJson, callback]() {
        HINTERNET hSession = WinHttpOpen(L"RawrXD-IDE/1.0", 
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, 
            WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) {
            if (callback) callback("Error: Failed to create HTTP session", true);
            return;
        }
        
        HINTERNET hConnect = WinHttpConnect(hSession, L"localhost", 
            static_cast<INTERNET_PORT>(11434), 0);
        
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            if (callback) callback("Error: Failed to connect to Ollama", true);
            return;
        }
        
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST",
            L"/api/generate", 
            NULL, WINHTTP_NO_REFERER, 
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_REFRESH);
        
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (callback) callback("Error: Failed to create request", true);
            return;
        }
        
        WinHttpAddRequestHeaders(hRequest, 
            L"Content-Type: application/json\r\n", 
            (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD);
        
        BOOL bResults = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)requestJson.c_str(),
            (DWORD)requestJson.length(),
            (DWORD)requestJson.length(), 0);
        
        if (bResults) {
            bResults = WinHttpReceiveResponse(hRequest, NULL);
        }
        
        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            if (callback) callback("Error: Failed to send request to Ollama", true);
            return;
        }
        
        // Read streaming response
        std::string accumulatedResponse;
        DWORD dwSize = 0;
        
        do {
            dwSize = 0;
            WinHttpQueryDataAvailable(hRequest, &dwSize);
            
            if (dwSize > 0) {
                std::vector<char> buffer(dwSize + 1);
                DWORD dwDownloaded = 0;
                WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded);
                buffer[dwDownloaded] = '\0';
                
                // Parse JSON lines (NDJSON format)
                std::string chunk(buffer.data());
                std::istringstream stream(chunk);
                std::string line;
                
                while (std::getline(stream, line)) {
                    if (line.empty()) continue;
                    
                    try {
                        auto j = json::parse(line);
                        
                        if (j.contains("response")) {
                            std::string token = j["response"];
                            accumulatedResponse += token;
                            
                            if (callback) {
                                callback(token, false);
                            }
                        }
                        
                        if (j.contains("done") && j["done"].template get<bool>()) {
                            // Stream complete
                            if (callback) {
                                callback("", true);
                            }
                        }
                    }
                    catch (...) {
                        // Skip malformed JSON lines
                    }
                }
            }
        } while (dwSize > 0);
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
    }).detach();
}

// ============================================================================
// Unified Chat Handler - Local GGUF first, Ollama fallback
// ============================================================================
void Win32IDE::HandleCopilotSend_Ollama()
{
    if (!m_hwndCopilotChatInput || !m_hwndCopilotChatOutput)
        return;
    
    wchar_t inputBuffer[4096] = {0};
    GetWindowTextW(m_hwndCopilotChatInput, inputBuffer, 4095);
    std::string userMessage = wideToUtf8(inputBuffer);
    
    if (userMessage.empty()) {
        return;
    }
    
    // Display user message
    std::string displayText = "\n[User]: " + userMessage + "\n\n[AI]: ";
    
    int len = GetWindowTextLengthW(m_hwndCopilotChatOutput);
    if (len > 0) {
        SendMessage(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
    }
    SendMessageW(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE, 
        (LPARAM)utf8ToWide(displayText).c_str());
    
    // Clear input
    SetWindowTextW(m_hwndCopilotChatInput, L"");
    
    // Add to history
    m_chatHistory.push_back({"user", userMessage});
    
    // PRIORITY 1: Try local native inference first (fully local, no HTTP)
    // INSTRUMENTATION: Log which branch is taken
    char logBuf[512];
    snprintf(logBuf, sizeof(logBuf), 
        "[AUDIT] Chat inference decision: m_nativeEngineLoaded=%s, m_nativeEngine=%s, m_loadedModelPath='%s'",
        m_nativeEngineLoaded ? "true" : "false",
        m_nativeEngine ? "non-null" : "null",
        m_loadedModelPath.c_str());
    OutputDebugStringA(logBuf);
    appendToOutput(logBuf, "Output", OutputSeverity::Info);
    
    if (m_nativeEngineLoaded && m_nativeEngine) {
        appendToOutput("[AUDIT] Chat: Using LOCAL native inference engine", "Output", OutputSeverity::Info);
        OutputDebugStringA("[AUDIT] Chat: Entering LOCAL inference branch\n");
        
        // Use async generation with streaming callback
        generateResponseAsync(userMessage,
            [this](const std::string& token, bool complete) {
                if (!m_hwndCopilotChatOutput) return;
                
                if (!token.empty()) {
                    int len = GetWindowTextLengthW(m_hwndCopilotChatOutput);
                    SendMessage(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
                    SendMessageW(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE,
                        (LPARAM)utf8ToWide(token).c_str());
                }
                
                if (complete) {
                    int len = GetWindowTextLengthW(m_hwndCopilotChatOutput);
                    SendMessage(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
                    SendMessageW(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE,
                        (LPARAM)L"\n\n");
                }
            });
        return;
    }
    
    // PRIORITY 2: Fallback to Ollama (requires external service)
    appendToOutput("[AUDIT] Chat: FALLING BACK to Ollama (local engine not ready)", "Output", OutputSeverity::Warning);
    OutputDebugStringA("[AUDIT] Chat: Entering OLLAMA fallback branch\n");
    sendChatMessageToOllama(userMessage, 
        [this](const std::string& token, bool complete) {
            if (!m_hwndCopilotChatOutput) return;
            
            if (!token.empty()) {
                int len = GetWindowTextLengthW(m_hwndCopilotChatOutput);
                SendMessage(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
                SendMessageW(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE,
                    (LPARAM)utf8ToWide(token).c_str());
            }
            
            if (complete) {
                int len = GetWindowTextLengthW(m_hwndCopilotChatOutput);
                SendMessage(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
                SendMessageW(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE,
                    (LPARAM)L"\n\n");
            }
        });
}

// ============================================================================
// Initialize chat panel - Local GGUF first, Ollama fallback
// ============================================================================
void Win32IDE::initializeChatPanelOllama()
{
    // Check local native engine status
    if (m_nativeEngineLoaded && m_nativeEngine) {
        OutputDebugStringA("[ChatPanel] Local native inference engine ready\n");
        
        // Update status bar
        if (m_hwndStatusBar) {
            SetWindowTextW(m_hwndStatusBar, L"Local AI: Ready (Native GGUF)");
        }
        
        // Still fetch Ollama models as fallback option
        fetchOllamaModelsAsync();
        return;
    }
    
    // No local model - try Ollama
    OutputDebugStringA("[ChatPanel] No local model loaded, checking Ollama...\n");
    
    if (m_hwndStatusBar) {
        SetWindowTextW(m_hwndStatusBar, L"Local AI: No GGUF loaded - checking Ollama...");
    }
    
    fetchOllamaModelsAsync();
}
