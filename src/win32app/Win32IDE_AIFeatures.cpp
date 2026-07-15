// ============================================================================
// Win32IDE_AIFeatures.cpp — AI Features Stub Implementation
// ============================================================================
// Stub implementations for AI features. These will be integrated with the
// actual AI backend in a future phase.
// ============================================================================

#include "Win32IDE.h"
#include "resource.h"
#include "IDELogger.h"
#include <nlohmann/json.hpp>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <sstream>
#include <functional>
#include <chrono>

using json = nlohmann::json;

// ============================================================================
// AI Model Router - Multi-provider support
// ============================================================================

namespace AIModelRouter {
    
    std::string getCurrentProvider() {
        return "Local_Ollama";  // Default to local
    }
    
    void setProvider(const std::string& provider) {
        // Stub - will be implemented with actual provider switching
    }
    
    std::string sendRequest(const std::string& provider, const std::string& prompt, const json& context) {
        // Stub - will be implemented with actual HTTP client
        return "{}";
    }
}

// ============================================================================
// AI Feature Functions - Stub Implementations
// ============================================================================

namespace Win32IDE_AI {

    std::string aiExplainCode(const std::string& code, const std::string& language) {
        // Stub - returns placeholder explanation
        return "Code explanation will be provided by AI model in a future update.";
    }
    
    std::string aiGenerateTests(const std::string& code, const std::string& language) {
        // Stub - returns placeholder test
        return "// Generated tests will appear here in a future update.\n// TEST: " + language + " test stub";
    }
    
    std::string aiSuggestRefactoring(const std::string& code, const std::string& language) {
        // Stub - returns placeholder refactoring suggestions
        return "Refactoring suggestions will be provided by AI model in a future update.";
    }
    
    std::string aiFixError(const std::string& code, const std::string& error, const std::string& language) {
        // Stub - returns placeholder fix
        return "// Error fix suggestions will be provided by AI model in a future update.";
    }
    
    std::string aiGenerateFromDescription(const std::string& description, const std::string& language) {
        // Stub - returns placeholder code
        return "// Generated code will appear here in a future update.\n// Description: " + description;
    }
    
    std::string aiCodeReview(const std::string& code, const std::string& language) {
        // Stub - returns placeholder review
        return "Code review comments will be provided by AI model in a future update.";
    }
    
    void initAIFeatures() {
        // Stub - initialization
    }
    
    void shutdownAIFeatures() {
        // Stub - cleanup
    }
    
    void setAIModelProvider(const std::string& provider) {
        // Stub - will be implemented with actual provider switching
    }

}  // namespace Win32IDE_AI

namespace AIModelRouter {

    enum class ModelProvider {
        OpenAI_GPT4,
        Anthropic_Claude,
        Google_Gemini,
        Local_Ollama,
        Local_Titan,
        Auto
    };

    struct ModelConfig {
        ModelProvider provider;
        std::string endpoint;
        std::string apiKey;
        std::string modelId;
        int maxTokens;
        double temperature;
        bool enabled;
    };

    static std::vector<ModelConfig> s_models = {
        {ModelProvider::OpenAI_GPT4, "https://api.openai.com/v1/chat/completions", "", "gpt-4-turbo", 4096, 0.7, true},
        {ModelProvider::Anthropic_Claude, "https://api.anthropic.com/v1/messages", "", "claude-3-opus", 4096, 0.7, true},
        {ModelProvider::Google_Gemini, "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent", "", "gemini-pro", 2048, 0.7, true},
        {ModelProvider::Local_Ollama, "http://localhost:11434/api/chat", "", "llama3", 4096, 0.8, true},
        {ModelProvider::Local_Titan, "http://localhost:8080/v1/chat/completions", "", "titan", 8192, 0.7, true}
    };

    static std::mutex s_routerMutex;
    static std::atomic<ModelProvider> s_preferredProvider{ModelProvider::Auto};

    void setPreferredProvider(ModelProvider provider) {
        s_preferredProvider = provider;
    }

    ModelProvider getPreferredProvider() {
        return s_preferredProvider;
    }

    ModelConfig getConfig(ModelProvider provider) {
        std::lock_guard<std::mutex> lock(s_routerMutex);
        for (const auto& cfg : s_models) {
            if (cfg.provider == provider && cfg.enabled) {
                return cfg;
            }
        }
        // Fallback to local
        for (const auto& cfg : s_models) {
            if (cfg.provider == ModelProvider::Local_Ollama) {
                return cfg;
            }
        }
        return s_models[0];
    }

    std::string buildRequest(ModelProvider provider, const std::string& systemPrompt, const std::string& userPrompt, int maxTokens) {
        json req;
        
        switch (provider) {
            case ModelProvider::OpenAI_GPT4:
                req["model"] = "gpt-4-turbo";
                {
                    json msg1;
                    msg1["role"] = "system";
                    msg1["content"] = systemPrompt;
                    json msg2;
                    msg2["role"] = "user";
                    msg2["content"] = userPrompt;
                    req["messages"] = json::array();
                    req["messages"].push_back(msg1);
                    req["messages"].push_back(msg2);
                }
                req["max_tokens"] = maxTokens;
                req["temperature"] = 0.7;
                break;
                
            case ModelProvider::Anthropic_Claude:
                req["model"] = "claude-3-opus-20240229";
                req["system"] = systemPrompt;
                {
                    json msg;
                    msg["role"] = "user";
                    msg["content"] = userPrompt;
                    req["messages"] = json::array();
                    req["messages"].push_back(msg);
                }
                req["max_tokens"] = maxTokens;
                break;
                
            case ModelProvider::Google_Gemini:
                {
                    json part;
                    part["text"] = systemPrompt + "\n\n" + userPrompt;
                    json parts = json::array();
                    parts.push_back(part);
                    json content;
                    content["parts"] = parts;
                    req["contents"] = json::array();
                    req["contents"].push_back(content);
                    req["generationConfig"] = json::object();
                    req["generationConfig"]["maxOutputTokens"] = maxTokens;
                    req["generationConfig"]["temperature"] = 0.7;
                }
                break;
                
            case ModelProvider::Local_Ollama:
            case ModelProvider::Local_Titan:
                req["model"] = (provider == ModelProvider::Local_Ollama) ? "llama3" : "titan";
                {
                    json msg1;
                    msg1["role"] = "system";
                    msg1["content"] = systemPrompt;
                    json msg2;
                    msg2["role"] = "user";
                    msg2["content"] = userPrompt;
                    req["messages"] = json::array();
                    req["messages"].push_back(msg1);
                    req["messages"].push_back(msg2);
                }
                req["stream"] = false;
                break;
                
            default:
                break;
        }
        
        return req.dump();
    }

    std::string parseResponse(ModelProvider provider, const std::string& response) {
        try {
            json resp = json::parse(response);
            
            switch (provider) {
                case ModelProvider::OpenAI_GPT4:
                    if (resp.contains("choices") && resp["choices"].is_array() && !resp["choices"].empty()) {
                        return resp["choices"].at(0)["message"]["content"].get<std::string>();
                    }
                    break;
                    
                case ModelProvider::Anthropic_Claude:
                    if (resp.contains("content") && resp["content"].is_array() && !resp["content"].empty()) {
                        return resp["content"].at(0)["text"].get<std::string>();
                    }
                    break;
                    
                case ModelProvider::Google_Gemini:
                    if (resp.contains("candidates") && resp["candidates"].is_array() && !resp["candidates"].empty()) {
                        return resp["candidates"].at(0)["content"]["parts"].at(0)["text"].get<std::string>();
                    }
                    break;
                    
                case ModelProvider::Local_Ollama:
                case ModelProvider::Local_Titan:
                    if (resp.contains("message") && resp["message"].contains("content")) {
                        return resp["message"]["content"].get<std::string>();
                    }
                    break;
                    
                default:
                    break;
            }
        } catch (...) {}
        
        return "";
    }
}

// ============================================================================
// AI REQUEST QUEUE - Background processing
// ============================================================================

struct AIRequest {
    std::string id;
    std::string type;
    std::string code;
    std::string context;
    std::string language;
    AIModelRouter::ModelProvider preferredProvider;
    std::shared_ptr<std::function<void(const std::string& result, bool success)>> callback;
};

static std::queue<AIRequest> s_requestQueue;
static std::mutex s_queueMutex;
static std::condition_variable s_queueCV;
static std::atomic<bool> s_queueRunning{false};
static std::thread s_workerThread;

static void processAIRequest(const AIRequest& req) {
    using namespace AIModelRouter;
    
    ModelProvider provider = req.preferredProvider;
    if (provider == ModelProvider::Auto) {
        provider = getPreferredProvider();
    }
    
    ModelConfig cfg = getConfig(provider);
    
    // Build system prompt based on request type
    std::string systemPrompt;
    std::string userPrompt = req.code;
    
    if (req.type == "explain") {
        systemPrompt = "You are an expert code reviewer. Explain the following code in clear, concise language. "
                      "Describe what it does, how it works, and any potential issues or improvements. "
                      "Format your response in markdown with code blocks where appropriate.";
    } else if (req.type == "test") {
        systemPrompt = "You are an expert test engineer. Generate comprehensive unit tests for the following code. "
                      "Include edge cases, error handling tests, and use appropriate testing frameworks. "
                      "Output only the test code, no explanations.";
        userPrompt = "Generate unit tests for:\n\n```" + req.language + "\n" + req.code + "\n```";
    } else if (req.type == "refactor") {
        systemPrompt = "You are an expert software architect. Suggest refactoring improvements for the following code. "
                      "Focus on readability, maintainability, performance, and design patterns. "
                      "Provide the refactored code with explanations of changes.";
    } else if (req.type == "fix") {
        systemPrompt = "You are an expert debugger. Analyze the following code and error, then provide a fix. "
                      "Explain what was wrong and how your fix addresses it.";
        userPrompt = "Code:\n```" + req.language + "\n" + req.code + "\n```\n\nError/Issue:\n" + req.context;
    } else if (req.type == "generate") {
        systemPrompt = "You are an expert programmer. Generate code based on the natural language description. "
                      "Output only the code, no explanations.";
        userPrompt = req.context + "\n\nLanguage: " + req.language;
    } else if (req.type == "review") {
        systemPrompt = "You are an expert code reviewer performing a pull request review. "
                      "Analyze the code changes and provide constructive feedback. "
                      "Focus on: bugs, security issues, performance, readability, and best practices. "
                      "Format as PR review comments.";
    }
    
    std::string requestBody = buildRequest(provider, systemPrompt, userPrompt, 4096);
    
    // Make HTTP request (simplified - real implementation would use WinHTTP properly)
    // For now, delegate to Ollama if available
    if (provider == ModelProvider::Local_Ollama || provider == ModelProvider::Local_Titan) {
        if (req.callback && *req.callback) {
            (*req.callback)("AI feature requires Ollama connection. Please ensure Ollama is running.", false);
        }
        return;
    }

    if (req.callback && *req.callback) {
        (*req.callback)("Cloud AI providers require API key configuration. Use local Ollama for now.", false);
    }
}

static void aiWorkerThread() {
    while (s_queueRunning) {
        AIRequest req;
        {
            std::unique_lock<std::mutex> lock(s_queueMutex);
            s_queueCV.wait(lock, []{ return !s_requestQueue.empty() || !s_queueRunning; });
            
            if (!s_queueRunning && s_requestQueue.empty()) break;
            if (s_requestQueue.empty()) continue;
            
            req = s_requestQueue.front();
            s_requestQueue.pop();
        }
        
        processAIRequest(req);
    }
}

// ============================================================================
// WIN32IDE AI FEATURE IMPLEMENTATIONS
// ============================================================================

void Win32IDE::initAIFeatures() {
    s_queueRunning = true;
    s_workerThread = std::thread(aiWorkerThread);
    LOG_INFO("[AIFeatures] Initialized with background worker thread");
}

void Win32IDE::shutdownAIFeatures() {
    s_queueRunning = false;
    s_queueCV.notify_all();
    if (s_workerThread.joinable()) {
        s_workerThread.join();
    }
    LOG_INFO("[AIFeatures] Shutdown complete");
}

void Win32IDE::aiExplainCode(const std::string& code, const std::string& language) {
    AIRequest req;
    req.id = "explain_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    req.type = "explain";
    req.code = code;
    req.language = language;
    req.preferredProvider = AIModelRouter::ModelProvider::Auto;
    req.callback = std::make_shared<std::function<void(const std::string& result, bool success)>>([this](const std::string& result, bool success) {
        // Post to UI thread
        PostMessageA(m_hwndMain, WM_APP + 500, success ? 1 : 0, reinterpret_cast<LPARAM>(new std::string(result)));
    });
    
    {
        std::lock_guard<std::mutex> lock(s_queueMutex);
        s_requestQueue.push(req);
    }
    s_queueCV.notify_one();
    
    appendToOutput("[AI] Requesting code explanation...", "General", OutputSeverity::Info);
}

void Win32IDE::aiGenerateTests(const std::string& code, const std::string& language) {
    AIRequest req;
    req.id = "test_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    req.type = "test";
    req.code = code;
    req.language = language;
    req.preferredProvider = AIModelRouter::ModelProvider::Auto;
    req.callback = std::make_shared<std::function<void(const std::string& result, bool success)>>([this](const std::string& result, bool success) {
        PostMessageA(m_hwndMain, WM_APP + 501, success ? 1 : 0, reinterpret_cast<LPARAM>(new std::string(result)));
    });
    
    {
        std::lock_guard<std::mutex> lock(s_queueMutex);
        s_requestQueue.push(req);
    }
    s_queueCV.notify_one();
    
    appendToOutput("[AI] Generating unit tests...", "General", OutputSeverity::Info);
}

void Win32IDE::aiSuggestRefactoring(const std::string& code, const std::string& language) {
    AIRequest req;
    req.id = "refactor_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    req.type = "refactor";
    req.code = code;
    req.language = language;
    req.preferredProvider = AIModelRouter::ModelProvider::Auto;
    req.callback = std::make_shared<std::function<void(const std::string& result, bool success)>>([this](const std::string& result, bool success) {
        PostMessageA(m_hwndMain, WM_APP + 502, success ? 1 : 0, reinterpret_cast<LPARAM>(new std::string(result)));
    });
    
    {
        std::lock_guard<std::mutex> lock(s_queueMutex);
        s_requestQueue.push(req);
    }
    s_queueCV.notify_one();
    
    appendToOutput("[AI] Analyzing refactoring opportunities...", "General", OutputSeverity::Info);
}

void Win32IDE::aiFixError(const std::string& code, const std::string& error, const std::string& language) {
    AIRequest req;
    req.id = "fix_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    req.type = "fix";
    req.code = code;
    req.context = error;
    req.language = language;
    req.preferredProvider = AIModelRouter::ModelProvider::Auto;
    req.callback = std::make_shared<std::function<void(const std::string& result, bool success)>>([this](const std::string& result, bool success) {
        PostMessageA(m_hwndMain, WM_APP + 503, success ? 1 : 0, reinterpret_cast<LPARAM>(new std::string(result)));
    });
    
    {
        std::lock_guard<std::mutex> lock(s_queueMutex);
        s_requestQueue.push(req);
    }
    s_queueCV.notify_one();
    
    appendToOutput("[AI] Analyzing error and generating fix...", "General", OutputSeverity::Info);
}

void Win32IDE::aiGenerateFromDescription(const std::string& description, const std::string& language) {
    AIRequest req;
    req.id = "generate_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    req.type = "generate";
    req.context = description;
    req.language = language;
    req.preferredProvider = AIModelRouter::ModelProvider::Auto;
    req.callback = std::make_shared<std::function<void(const std::string& result, bool success)>>([this](const std::string& result, bool success) {
        PostMessageA(m_hwndMain, WM_APP + 504, success ? 1 : 0, reinterpret_cast<LPARAM>(new std::string(result)));
    });
    
    {
        std::lock_guard<std::mutex> lock(s_queueMutex);
        s_requestQueue.push(req);
    }
    s_queueCV.notify_one();
    
    appendToOutput("[AI] Generating code from description...", "General", OutputSeverity::Info);
}

void Win32IDE::aiCodeReview(const std::string& diff) {
    AIRequest req;
    req.id = "review_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    req.type = "review";
    req.code = diff;
    req.preferredProvider = AIModelRouter::ModelProvider::Auto;
    req.callback = std::make_shared<std::function<void(const std::string& result, bool success)>>([this](const std::string& result, bool success) {
        PostMessageA(m_hwndMain, WM_APP + 505, success ? 1 : 0, reinterpret_cast<LPARAM>(new std::string(result)));
    });
    
    {
        std::lock_guard<std::mutex> lock(s_queueMutex);
        s_requestQueue.push(req);
    }
    s_queueCV.notify_one();
    
    appendToOutput("[AI] Performing code review...", "General", OutputSeverity::Info);
}

void Win32IDE::setAIModelProvider(const std::string& provider) {
    using namespace AIModelRouter;
    
    if (provider == "gpt4" || provider == "openai") {
        setPreferredProvider(ModelProvider::OpenAI_GPT4);
    } else if (provider == "claude" || provider == "anthropic") {
        setPreferredProvider(ModelProvider::Anthropic_Claude);
    } else if (provider == "gemini" || provider == "google") {
        setPreferredProvider(ModelProvider::Google_Gemini);
    } else if (provider == "ollama" || provider == "local") {
        setPreferredProvider(ModelProvider::Local_Ollama);
    } else if (provider == "titan") {
        setPreferredProvider(ModelProvider::Local_Titan);
    } else {
        setPreferredProvider(ModelProvider::Auto);
    }
    
    appendToOutput("[AI] Model provider set to: " + provider, "General", OutputSeverity::Info);
}

// ============================================================================
// CONTEXT-AWARE COMPLETIONS - Project-aware suggestions
// ============================================================================

struct ContextAwareCompletion {
    std::string text;
    std::string source;  // "project", "import", "pattern", "ai"
    double confidence;
    std::string documentation;
};

static std::vector<ContextAwareCompletion> s_recentCompletions;
static std::mutex s_completionCacheMutex;

void Win32IDE::initContextAwareCompletions() {
    s_recentCompletions.clear();
    LOG_INFO("[ContextCompletions] Initialized");
}

std::vector<std::string> Win32IDE::getContextAwareCompletions(const std::string& prefix, const std::string& context) {
    std::vector<std::string> results;
    
    // 1. Project symbol completions (from semantic index)
    // 2. Import-based completions (from imports in current file)
    // 3. Pattern-based completions (common idioms)
    // 4. AI-suggested completions (from ghost text)
    
    // Pattern-based completions
    static const std::vector<std::pair<std::string, std::vector<std::string>>> patterns = {
        {"for", {"for (int i = 0; i < N; i++) {\n    \n}", "for (const auto& item : container) {\n    \n}"}},
        {"if", {"if (condition) {\n    \n}", "if (auto* ptr = dynamic_cast<T*>(obj)) {\n    \n}"}},
        {"while", {"while (condition) {\n    \n}"}},
        {"switch", {"switch (value) {\n    case A:\n        break;\n    case B:\n        break;\n    default:\n        break;\n}"}},
        {"try", {"try {\n    \n} catch (const std::exception& e) {\n    \n}"}},
        {"class", {"class ClassName {\npublic:\n    ClassName();\n    ~ClassName();\nprivate:\n};"}},
        {"struct", {"struct StructName {\n    \n};"}},
        {"template", {"template<typename T>\n"}},
        {"namespace", {"namespace NamespaceName {\n    \n}"}}
    };
    
    std::string lowerPrefix = prefix;
    std::transform(lowerPrefix.begin(), lowerPrefix.end(), lowerPrefix.begin(), ::tolower);
    
    for (const auto& [key, completions] : patterns) {
        if (key.find(lowerPrefix) == 0) {
            for (const auto& completion : completions) {
                results.push_back(completion);
            }
        }
    }
    
    return results;
}

// ============================================================================
// MENU COMMAND HANDLERS
// ============================================================================

void Win32IDE::cmdAIExplainSelection() {
    if (!m_hwndEditor) return;
    
    CHARRANGE sel;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
    
    if (sel.cpMin >= sel.cpMax) {
        appendToOutput("[AI] Please select some code to explain.", "General", OutputSeverity::Warning);
        return;
    }
    
    std::string text(sel.cpMax - sel.cpMin + 1, '\0');
    TEXTRANGEA tr;
    tr.chrg.cpMin = sel.cpMin;
    tr.chrg.cpMax = sel.cpMax;
    tr.lpstrText = &text[0];
    SendMessage(m_hwndEditor, EM_GETTEXTRANGE, 0, reinterpret_cast<LPARAM>(&tr));
    
    aiExplainCode(text, lspLanguageString(detectLanguageForFile(m_currentFile)));
}

void Win32IDE::cmdAIGenerateTests() {
    if (!m_hwndEditor) return;
    
    CHARRANGE sel;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
    
    std::string text;
    if (sel.cpMin < sel.cpMax) {
        text.resize(sel.cpMax - sel.cpMin + 1);
        TEXTRANGEA tr;
        tr.chrg.cpMin = sel.cpMin;
        tr.chrg.cpMax = sel.cpMax;
        tr.lpstrText = &text[0];
        SendMessage(m_hwndEditor, EM_GETTEXTRANGE, 0, reinterpret_cast<LPARAM>(&tr));
    } else {
        // Get entire file
        int len = GetWindowTextLengthA(m_hwndEditor);
        text.resize(len + 1);
        GetWindowTextA(m_hwndEditor, &text[0], len + 1);
    }
    
    aiGenerateTests(text, lspLanguageString(detectLanguageForFile(m_currentFile)));
}

void Win32IDE::cmdAIRefactorSelection() {
    if (!m_hwndEditor) return;
    
    CHARRANGE sel;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
    
    if (sel.cpMin >= sel.cpMax) {
        appendToOutput("[AI] Please select some code to refactor.", "General", OutputSeverity::Warning);
        return;
    }
    
    std::string text(sel.cpMax - sel.cpMin + 1, '\0');
    TEXTRANGEA tr;
    tr.chrg.cpMin = sel.cpMin;
    tr.chrg.cpMax = sel.cpMax;
    tr.lpstrText = &text[0];
    SendMessage(m_hwndEditor, EM_GETTEXTRANGE, 0, reinterpret_cast<LPARAM>(&tr));
    
    aiSuggestRefactoring(text, lspLanguageString(detectLanguageForFile(m_currentFile)));
}

void Win32IDE::cmdAIFixCurrentError() {
    // Get current diagnostic from LSP
    std::string error;
    {
        std::lock_guard<std::mutex> lock(m_lspDiagnosticsMutex);
        if (!m_lspDiagnostics.empty()) {
            auto it = m_lspDiagnostics.begin();
            if (!it->second.empty()) {
                error = it->second[0].message;
            }
        }
    }
    
    if (error.empty()) {
        appendToOutput("[AI] No error diagnostics available.", "General", OutputSeverity::Warning);
        return;
    }
    
    // Get current file content
    std::string code;
    if (m_hwndEditor) {
        int len = GetWindowTextLengthA(m_hwndEditor);
        code.resize(len + 1);
        GetWindowTextA(m_hwndEditor, &code[0], len + 1);
    }
    
    aiFixError(code, error, lspLanguageString(detectLanguageForFile(m_currentFile)));
}

void Win32IDE::cmdAIGenerateFromPrompt() {
    // Show input dialog for natural language description
    // Use a simple static dialog proc with lParam for buffer
    struct PromptDlgData {
        char* buffer;
        size_t bufferSize;
    };
    char buffer[4096] = {};
    PromptDlgData dlgData = { buffer, sizeof(buffer) };
    
    auto dlgProc = [](HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) -> INT_PTR {
        if (msg == WM_INITDIALOG) {
            SetWindowTextA(hDlg, "Generate Code from Description");
            SetWindowLongPtrA(hDlg, DWLP_USER, lParam);
            return TRUE;
        }
        if (msg == WM_COMMAND) {
            auto* data = reinterpret_cast<PromptDlgData*>(GetWindowLongPtrA(hDlg, DWLP_USER));
            if (LOWORD(wParam) == IDOK && data) {
                GetDlgItemTextA(hDlg, IDC_INPUT_EDIT, data->buffer, static_cast<int>(data->bufferSize));
                EndDialog(hDlg, IDOK);
                return TRUE;
            }
            if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }
        }
        return FALSE;
    };
    
    if (DialogBoxParamA(m_hInstance, MAKEINTRESOURCEA(IDD_INPUT_DIALOG), m_hwndMain, dlgProc, 
        reinterpret_cast<LPARAM>(&dlgData)) == IDOK) {
        if (strlen(buffer) > 0) {
            aiGenerateFromDescription(buffer, lspLanguageString(detectLanguageForFile(m_currentFile)));
        }
    }
}

void Win32IDE::cmdAICodeReview() {
    // Get git diff for current file or staged changes
    std::string diff;
    
    // For now, get current file content
    if (m_hwndEditor) {
        int len = GetWindowTextLengthA(m_hwndEditor);
        diff.resize(len + 1);
        GetWindowTextA(m_hwndEditor, &diff[0], len + 1);
    }
    
    aiCodeReview(diff);
}