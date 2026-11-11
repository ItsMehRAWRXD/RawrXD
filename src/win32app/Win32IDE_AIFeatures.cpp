// ============================================================================
// Win32IDE_AIFeatures_Real.cpp — REAL AI Features Implementation
// ============================================================================
// Connects to Ollama backend for actual AI functionality
// Replaces: Win32IDE_AIFeatures.cpp (stub implementation)
// ============================================================================

#include "Win32IDE.h"
#include "resource.h"
#include "IDELogger.h"
#include <windows.h>
#include <winhttp.h>
#include <nlohmann/json.hpp>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <sstream>
#include <functional>
#include <chrono>

#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

// ============================================================================
// Ollama HTTP Client
// ============================================================================

namespace OllamaClient {
    
    static std::string g_ollamaUrl = "http://localhost:11434";
    static std::string g_defaultModel = "qwen2.5-coder:14b";
    
    void setUrl(const std::string& url) {
        g_ollamaUrl = url;
    }
    
    std::string getUrl() {
        return g_ollamaUrl;
    }
    
    void setDefaultModel(const std::string& model) {
        g_defaultModel = model;
    }
    
    std::string getDefaultModel() {
        return g_defaultModel;
    }
    
    // Simple HTTP POST to Ollama
    std::string httpPost(const std::string& endpoint, const std::string& body) {
        std::string response;
        
        HINTERNET hSession = WinHttpOpen(L"RawrXD-IDE/1.0", 
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, 
            WINHTTP_NO_PROXY_BYPASS, 0);
        
        if (!hSession) return "";
        
        // Parse URL
        std::wstring serverName = L"localhost";
        INTERNET_PORT port = 11434;
        
        HINTERNET hConnect = WinHttpConnect(hSession, serverName.c_str(), port, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return "";
        }
        
        std::wstring wideEndpoint(endpoint.begin(), endpoint.end());
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wideEndpoint.c_str(),
            NULL, WINHTTP_NO_REFERER, 
            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }
        
        // Add Content-Type header
        WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1L, 
            WINHTTP_ADDREQ_FLAG_ADD);
        
        BOOL bResults = WinHttpSendRequest(hRequest, 
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)body.c_str(), (DWORD)body.length(), 
            (DWORD)body.length(), 0);
        
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
                    response += buffer.data();
                }
            } while (dwSize > 0);
        }
        
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        
        return response;
    }
    
    // Check if Ollama is available
    bool isAvailable() {
        std::string response = httpPost("/api/tags", "");
        return !response.empty() && response.find("models") != std::string::npos;
    }
    
    // Generate completion
    std::string generate(const std::string& prompt, const std::string& model = "") {
        std::string useModel = model.empty() ? g_defaultModel : model;
        
        json request;
        request["model"] = useModel;
        request["prompt"] = prompt;
        request["stream"] = false;
        
        std::string response = httpPost("/api/generate", request.dump());
        
        if (!response.empty()) {
            try {
                json j = json::parse(response);
                if (j.contains("response")) {
                    return j["response"].get<std::string>();
                }
            } catch (...) {
                // Parse error
            }
        }
        
        return "";
    }
    
    // Chat completion
    std::string chat(const std::vector<std::pair<std::string, std::string>>& messages, 
                     const std::string& model = "") {
        std::string useModel = model.empty() ? g_defaultModel : model;
        
        json request;
        request["model"] = useModel;
        request["stream"] = false;
        
        json msgs = json::array();
        for (const auto& msg : messages) {
            json m;
            m["role"] = msg.first;
            m["content"] = msg.second;
            msgs.push_back(m);
        }
        request["messages"] = msgs;
        
        std::string response = httpPost("/api/chat", request.dump());
        
        if (!response.empty()) {
            try {
                json j = json::parse(response);
                if (j.contains("message") && j["message"].contains("content")) {
                    return j["message"]["content"].get<std::string>();
                }
            } catch (...) {
                // Parse error
            }
        }
        
        return "";
    }
}

// ============================================================================
// REAL AI Feature Functions
// ============================================================================

namespace Win32IDE_AI {

    static std::string g_currentProvider = "Local_Ollama";
    static bool g_initialized = false;
    
    void initAIFeatures() {
        g_initialized = true;
        OutputDebugStringA("[AI] Features initialized with Ollama backend\n");
    }
    
    void shutdownAIFeatures() {
        g_initialized = false;
        OutputDebugStringA("[AI] Features shutdown\n");
    }
    
    bool isAvailable() {
        return OllamaClient::isAvailable();
    }
    
    void setAIModelProvider(const std::string& provider) {
        g_currentProvider = provider;
        if (provider == "Local_Ollama") {
            OllamaClient::setUrl("http://localhost:11434");
        }
    }
    
    std::string getAIModelProvider() {
        return g_currentProvider;
    }
    
    std::string aiExplainCode(const std::string& code, const std::string& language) {
        if (!isAvailable()) {
            return "Error: Ollama not available. Please ensure Ollama is running on localhost:11434";
        }
        
        std::string prompt = "Explain this " + language + " code:\n\n```" + language + "\n" + code + "\n```\n\nProvide a clear explanation of what this code does:";
        
        std::string response = OllamaClient::generate(prompt);
        if (!response.empty()) {
            return response;
        }
        
        return "Error: Failed to get explanation from AI model.";
    }
    
    std::string aiGenerateTests(const std::string& code, const std::string& language) {
        if (!isAvailable()) {
            return "Error: Ollama not available. Please ensure Ollama is running on localhost:11434";
        }
        
        std::string prompt = "Generate unit tests for this " + language + " code:\n\n```" + language + "\n" + code + "\n```\n\nProvide complete test code:";
        
        std::string response = OllamaClient::generate(prompt);
        if (!response.empty()) {
            return response;
        }
        
        return "Error: Failed to generate tests from AI model.";
    }
    
    std::string aiSuggestRefactoring(const std::string& code, const std::string& language) {
        if (!isAvailable()) {
            return "Error: Ollama not available. Please ensure Ollama is running on localhost:11434";
        }
        
        std::string prompt = "Suggest refactoring improvements for this " + language + " code:\n\n```" + language + "\n" + code + "\n```\n\nProvide specific refactoring suggestions:";
        
        std::string response = OllamaClient::generate(prompt);
        if (!response.empty()) {
            return response;
        }
        
        return "Error: Failed to get refactoring suggestions from AI model.";
    }
    
    std::string aiFixError(const std::string& code, const std::string& error, const std::string& language) {
        if (!isAvailable()) {
            return "Error: Ollama not available. Please ensure Ollama is running on localhost:11434";
        }
        
        std::string prompt = "Fix this error in " + language + " code:\n\nError: " + error + "\n\nCode:\n```" + language + "\n" + code + "\n```\n\nProvide the fixed code:";
        
        std::string response = OllamaClient::generate(prompt);
        if (!response.empty()) {
            return response;
        }
        
        return "Error: Failed to get fix from AI model.";
    }
    
    std::string aiGenerateFromDescription(const std::string& description, const std::string& language) {
        if (!isAvailable()) {
            return "Error: Ollama not available. Please ensure Ollama is running on localhost:11434";
        }
        
        std::string prompt = "Generate " + language + " code for: " + description + "\n\nProvide complete, working code:";
        
        std::string response = OllamaClient::generate(prompt);
        if (!response.empty()) {
            return response;
        }
        
        return "Error: Failed to generate code from AI model.";
    }
    
    std::string aiCodeReview(const std::string& code, const std::string& language) {
        if (!isAvailable()) {
            return "Error: Ollama not available. Please ensure Ollama is running on localhost:11434";
        }
        
        std::string prompt = "Review this " + language + " code for issues, best practices, and improvements:\n\n```" + language + "\n" + code + "\n```\n\nProvide a detailed code review:";
        
        std::string response = OllamaClient::generate(prompt);
        if (!response.empty()) {
            return response;
        }
        
        return "Error: Failed to get code review from AI model.";
    }
    
    // Chat with AI (multi-turn)
    std::string aiChat(const std::string& message, const std::vector<std::pair<std::string, std::string>>& history) {
        if (!isAvailable()) {
            return "Error: Ollama not available. Please ensure Ollama is running on localhost:11434";
        }
        
        std::vector<std::pair<std::string, std::string>> messages = history;
        messages.push_back({"user", message});
        
        std::string response = OllamaClient::chat(messages);
        if (!response.empty()) {
            return response;
        }
        
        return "Error: Failed to get response from AI model.";
    }

}  // namespace Win32IDE_AI

// ============================================================================
// Backward Compatibility - Keep old namespace working
// ============================================================================

namespace AIModelRouter {
    std::string getCurrentProvider() {
        return Win32IDE_AI::getAIModelProvider();
    }
    
    void setProvider(const std::string& provider) {
        Win32IDE_AI::setAIModelProvider(provider);
    }
    
    std::string sendRequest(const std::string& provider, const std::string& prompt, const json& context) {
        return Win32IDE_AI::aiChat(prompt, {});
    }
}
