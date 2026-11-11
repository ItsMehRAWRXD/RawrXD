// ============================================================================
// RawrXD GPT/Codex CLI Implementation
// Unified interface for OpenAI GPT and GitHub Copilot
// ============================================================================

#include "CodexCLI.hpp"
#include "JsonLite.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

namespace RawrXD {
namespace Codex {

CodexCLI::CodexCLI() = default;
CodexCLI::~CodexCLI() = default;

bool CodexCLI::Initialize(const Config& config) {
    m_config = config;
    
    // Auto-detect provider from environment
    m_config.AutoDetect();
    
    // Check for OLLAMA_MODEL environment variable
    const char* ollamaModel = getenv("OLLAMA_MODEL");
    if (ollamaModel && *ollamaModel) {
        m_config.model = ollamaModel;
    }
    
    // For OpenAI, API key is required
    if (m_config.provider == Provider::OpenAI && m_config.apiKey.empty()) {
        // Try to load from environment
        const char* envKey = getenv("OPENAI_API_KEY");
        if (envKey) {
            m_config.apiKey = envKey;
        } else {
            m_lastError = "API key not provided. Set OPENAI_API_KEY environment variable.";
            return false;
        }
    }
    
    // Initialize HTTP client
    if (!m_httpClient.Initialize()) {
        m_lastError = m_httpClient.GetLastError();
        return false;
    }
    
    m_httpClient.SetTimeout(30000, 30000, m_config.timeoutMs);
    
#ifdef RAWRXD_ENABLE_CODEX_EVENTBUS
    // Initialize event bus (optional - don't fail if shared memory not available)
    if (m_eventBusEnabled) {
        m_eventBus.Initialize();
    }
#endif
    
    m_initialized = true;
    const char* providerName = (m_config.provider == Provider::Ollama) ? "Ollama" : "OpenAI";
    printf("[CodexCLI] Initialized with %s model: %s\n", providerName, m_config.model.c_str());
    return true;
}

std::string CodexCLI::Complete(const std::string& prompt) {
    if (!m_initialized) {
        m_lastError = "Not initialized";
        return "";
    }
    
    std::string url = m_config.baseUrl;
    if (m_config.provider == Provider::Ollama) {
        url += "/api/chat";
    } else {
        url += "/v1/chat/completions";
    }
    std::string body = BuildRequestJson(prompt, false);
    std::string response;
    
    if (!HttpPost(url, body, response)) {
        // m_lastError is already set by HttpPost
        return "";
    }
    
    return ParseResponse(response);
}

bool CodexCLI::CompleteStreaming(const std::string& prompt, ResponseCallback callback) {
    if (!m_initialized) {
        m_lastError = "Not initialized";
        return false;
    }
    
    // Generate unique session ID for this streaming request
    uint64_t sessionId = ++m_sessionId;
    m_chunkIndex = 0;
    
    // Publish stream started event
    PublishStreamStarted(prompt);
    
    std::string url = m_config.baseUrl;
    if (m_config.provider == Provider::Ollama) {
        url += "/api/chat";
    } else {
        url += "/v1/chat/completions";
    }
    std::string body = BuildRequestJson(prompt, true);
    
    // Wrap callback to also publish to event bus
    auto wrappedCallback = [this, callback, sessionId](const std::string& chunk, bool isFinal) {
        // Call original callback
        callback(chunk, isFinal);
        
        // Publish to event bus
        PublishStreamChunk(chunk, isFinal);
    };
    
    bool success = HttpPostStreaming(url, body, wrappedCallback);
    
    if (success) {
        PublishStreamCompleted();
    } else {
        PublishStreamError(m_lastError);
    }
    
    return success;
}

void CodexCLI::RunREPL() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║           RawrXD GPT/Codex Interactive Shell                 ║\n");
    printf("║                    Model: %-20s             ║\n", m_config.model.c_str());
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("Type 'exit' to quit, 'help' for commands\n\n");
    
    std::string input;
    char buffer[4096];
    
    while (true) {
        printf("codex> ");
        fflush(stdout);
        
        if (!fgets(buffer, sizeof(buffer), stdin)) {
            break;
        }
        
        input = buffer;
        // Remove newline
        if (!input.empty() && input.back() == '\n') {
            input.pop_back();
        }
        
        if (input == "exit" || input == "quit") {
            printf("Goodbye!\n");
            break;
        }
        
        if (input == "help") {
            printf("Commands:\n");
            printf("  help    - Show this help\n");
            printf("  exit    - Exit REPL\n");
            printf("  clear   - Clear screen\n");
            printf("  model   - Show current model\n");
            continue;
        }
        
        if (input == "clear") {
            system("cls");
            continue;
        }
        
        if (input == "model") {
            printf("Current model: %s\n", m_config.model.c_str());
            continue;
        }
        
        if (input.empty()) {
            continue;
        }
        
        // Process the prompt
        printf("\nThinking...\n\n");
        
        std::string response = Complete(input);
        if (!response.empty()) {
            printf("%s\n\n", response.c_str());
        } else {
            printf("Error: %s\n\n", GetLastError());
        }
    }
}

int CodexCLI::ExecuteCommand(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <command> [options]\n", argv[0]);
        printf("\nCommands:\n");
        printf("  complete <prompt>     Send single completion request\n");
        printf("  stream <prompt>       Stream completion response\n");
        printf("  repl                  Start interactive REPL\n");
        printf("  version               Show version info\n");
        printf("  help                  Show this help\n");
        printf("\nOptions:\n");
        printf("  -h, --help            Show help for a command\n");
        printf("  -v, --version         Show version\n");
        printf("\nExit Codes:\n");
        printf("  0  Success\n");
        printf("  1  General error\n");
        printf("  2  Misuse of command\n");
        printf("  3  Invalid API key\n");
        printf("  4  Network error\n");
        printf("  5  Rate limited\n");
        printf("  6  Invalid model\n");
        printf("  7  Provider unavailable\n");
        printf("  8  JSON parse error\n");
        printf("  9  Timeout\n");
        return static_cast<int>(ExitCode::MisuseOfCommand);
    }
    
    std::string command = argv[1];
    
    // Handle global help flags
    if (command == "help" || command == "--help" || command == "-h") {
        printf("RawrXD Codex - GPT/Codex CLI/GUI Interface\n");
        printf("Version: 1.0.0\n\n");
        printf("Usage: %s <command> [args...]\n\n", argv[0]);
        printf("Commands:\n");
        printf("  complete <prompt>     Generate completion for prompt\n");
        printf("  stream <prompt>         Stream completion tokens\n");
        printf("  repl                    Start interactive REPL\n");
        printf("  version                 Show version info\n");
        printf("  help                    Show this help\n\n");
        printf("Environment:\n");
        printf("  OPENAI_API_KEY          API key for OpenAI\n");
        printf("  OLLAMA_HOST             Ollama server host (default: localhost:11434)\n");
        printf("  OLLAMA_MODEL            Model to use (e.g., gemma3:27b-it-qat)\n\n");
        printf("Examples:\n");
        printf("  %s complete \"Write hello world in C++\"\n", argv[0]);
        printf("  %s stream \"Explain quantum computing\"\n", argv[0]);
        printf("  %s repl\n", argv[0]);
        return static_cast<int>(ExitCode::Success);
    }
    
    if (command == "version" || command == "--version" || command == "-v") {
        printf("RawrXD Codex CLI v1.0.0\n");
        printf("Model: %s\n", m_config.model.c_str());
        return static_cast<int>(ExitCode::Success);
    }
    
    if (command == "repl") {
        RunREPL();
        return static_cast<int>(ExitCode::Success);
    }
    
    if (command == "complete" && argc >= 3) {
        std::string prompt = argv[2];
        for (int i = 3; i < argc; i++) {
            prompt += " ";
            prompt += argv[i];
        }
        
        std::string response = Complete(prompt);
        if (!response.empty()) {
            printf("%s\n", response.c_str());
            return static_cast<int>(ExitCode::Success);
        } else {
            fprintf(stderr, "Error: %s\n", GetLastError());
            // Map error to appropriate exit code
            std::string err = GetLastError();
            if (err.find("API key") != std::string::npos) {
                return static_cast<int>(ExitCode::InvalidApiKey);
            } else if (err.find("network") != std::string::npos || err.find("connect") != std::string::npos) {
                return static_cast<int>(ExitCode::NetworkError);
            } else if (err.find("rate") != std::string::npos) {
                return static_cast<int>(ExitCode::RateLimited);
            } else if (err.find("model") != std::string::npos) {
                return static_cast<int>(ExitCode::InvalidModel);
            } else if (err.find("timeout") != std::string::npos) {
                return static_cast<int>(ExitCode::Timeout);
            }
            return static_cast<int>(ExitCode::GeneralError);
        }
    }
    
    if (command == "stream" && argc >= 3) {
        std::string prompt = argv[2];
        for (int i = 3; i < argc; i++) {
            prompt += " ";
            prompt += argv[i];
        }
        
        bool first = true;
        auto callback = [&first](const std::string& chunk, bool isFinal) {
            if (first) {
                printf("\n");
                first = false;
            }
            printf("%s", chunk.c_str());
            fflush(stdout);
            if (isFinal) {
                printf("\n");
            }
        };
        
        if (CompleteStreaming(prompt, callback)) {
            return static_cast<int>(ExitCode::Success);
        } else {
            fprintf(stderr, "Error: %s\n", GetLastError());
            return static_cast<int>(ExitCode::GeneralError);
        }
    }
    
    fprintf(stderr, "Unknown command: %s\n", command.c_str());
    return static_cast<int>(ExitCode::MisuseOfCommand);
}

std::string CodexCLI::BuildRequestJson(const std::string& prompt, bool stream) {
    JsonValue request;
    request["model"] = m_config.model;
    
    // Create messages array
    JsonValue messages = JsonValue::MakeArray();
    JsonValue msg;
    msg["role"] = "user";
    msg["content"] = prompt;
    messages.Push(msg);
    request["messages"] = messages;
    
    request["max_tokens"] = static_cast<double>(m_config.maxTokens);
    request["temperature"] = m_config.temperature;
    request["stream"] = stream;
    
    return request.Dump();
}

std::string CodexCLI::ParseResponse(const std::string& json) {
    try {
        auto response = JsonValue::Parse(json);
        
        // OpenAI format: choices[0].message.content
        if (response.HasKey("choices") && response["choices"].Size() > 0) {
            return response["choices"][0]["message"]["content"].AsString();
        }
        
        // Ollama format: message.content
        if (response.HasKey("message") && response["message"].HasKey("content")) {
            return response["message"]["content"].AsString();
        }
        
        if (response.HasKey("error")) {
            m_lastError = response["error"]["message"].AsString();
            return "";
        }
    } catch (const std::exception& e) {
        m_lastError = std::string("JSON parse error: ") + e.what();
    }
    return "";
}

std::string CodexCLI::ParseStreamChunk(const std::string& chunk) {
    // Parse SSE format: data: {...}
    std::string result;
    size_t pos = 0;
    
    while (pos < chunk.size()) {
        // Find "data: " prefix
        size_t dataPos = chunk.find("data: ", pos);
        if (dataPos == std::string::npos) break;
        
        size_t lineEnd = chunk.find('\n', dataPos);
        if (lineEnd == std::string::npos) lineEnd = chunk.size();
        
        std::string data = chunk.substr(dataPos + 6, lineEnd - dataPos - 6);
        
        // Check for [DONE] sentinel
        if (data == "[DONE]") {
            break;
        }
        
        // Parse JSON content
        try {
            auto json = JsonValue::Parse(data);
            if (json.HasKey("choices") && json["choices"].Size() > 0) {
                const auto& delta = json["choices"][0]["delta"];
                if (delta.HasKey("content")) {
                    result += delta["content"].AsString();
                }
            }
        } catch (...) {
            // Skip malformed chunks
        }
        
        pos = lineEnd + 1;
    }
    
    return result;
}

bool CodexCLI::HttpPost(const std::string& url, const std::string& body, std::string& response) {
    // Convert URL to wide string
    std::wstring wurl(url.begin(), url.end());
    
    // Build headers
    std::string headers = "Content-Type: application/json\r\n";
    if (m_config.provider == Provider::OpenAI) {
        headers += "Authorization: Bearer " + m_config.apiKey + "\r\n";
    }
    
    if (!m_httpClient.Post(wurl, headers, body, response)) {
        m_lastError = m_httpClient.GetLastError();
        return false;
    }
    return true;
}

bool CodexCLI::HttpPostStreaming(const std::string& url, const std::string& body, ResponseCallback callback) {
    // Convert URL to wide string
    std::wstring wurl(url.begin(), url.end());
    
    // Build headers
    std::string headers = "Content-Type: application/json\r\n";
    if (m_config.provider == Provider::OpenAI) {
        headers += "Authorization: Bearer " + m_config.apiKey + "\r\n";
    }
    headers += "Accept: text/event-stream\r\n";
    
    // Buffer for accumulating SSE data
    std::string sseBuffer;
    
    return m_httpClient.PostStreaming(wurl, headers, body, 
        [&](const std::string& chunk, bool isFinal) {
            if (isFinal) {
                callback("", true);
                return;
            }
            
            sseBuffer += chunk;
            
            // Process complete SSE lines
            size_t pos = 0;
            while (pos < sseBuffer.size()) {
                size_t lineEnd = sseBuffer.find('\n', pos);
                if (lineEnd == std::string::npos) break;
                
                std::string line = sseBuffer.substr(pos, lineEnd - pos);
                
                // Check for data: prefix
                if (line.substr(0, 6) == "data: ") {
                    std::string data = line.substr(6);
                    
                    // Check for [DONE] sentinel (OpenAI)
                    if (data == "[DONE]") {
                        callback("", true);
                        return;
                    }
                    
                    // Parse and extract content
                    try {
                        auto json = JsonValue::Parse(data);
                        
                        // OpenAI format: choices[0].delta.content
                        if (json.HasKey("choices") && json["choices"].Size() > 0) {
                            const auto& delta = json["choices"][0]["delta"];
                            if (delta.HasKey("content")) {
                                std::string content = delta["content"].AsString();
                                if (!content.empty()) {
                                    callback(content, false);
                                }
                            }
                        }
                        // Ollama format: message.content
                        else if (json.HasKey("message") && json["message"].HasKey("content")) {
                            std::string content = json["message"]["content"].AsString();
                            if (!content.empty()) {
                                callback(content, false);
                            }
                            // Check if Ollama stream is done
                            if (json.HasKey("done") && json["done"].AsBool()) {
                                callback("", true);
                                return;
                            }
                        }
                    } catch (...) {
                        // Skip malformed JSON
                    }
                }
                
                pos = lineEnd + 1;
            }
            
            // Keep incomplete data in buffer
            if (pos > 0) {
                sseBuffer = sseBuffer.substr(pos);
            }
        });
}

// Event publishing helpers
void CodexCLI::PublishStreamStarted(const std::string& prompt) {
#ifdef RAWRXD_ENABLE_CODEX_EVENTBUS
    if (!m_eventBusEnabled || !m_eventBus.IsConnected()) return;
    
    uint32_t providerType = (m_config.provider == Provider::Ollama) ? 1u : 0u;
    m_eventBus.PublishRequestSubmitted(
        m_sessionId.load(),
        providerType,
        true, // isStreaming
        m_config.model,
        prompt
    );
    
    m_eventBus.PublishStreamStarted(
        m_sessionId.load(),
        m_config.model,
        prompt
    );
#endif
}

void CodexCLI::PublishStreamChunk(const std::string& chunk, bool isFinal) {
#ifdef RAWRXD_ENABLE_CODEX_EVENTBUS
    if (!m_eventBusEnabled || !m_eventBus.IsConnected()) return;
    
    uint32_t idx = m_chunkIndex.fetch_add(1);
    m_eventBus.PublishStreamChunk(
        m_sessionId.load(),
        idx,
        chunk,
        isFinal
    );
#endif
}

void CodexCLI::PublishStreamCompleted() {
#ifdef RAWRXD_ENABLE_CODEX_EVENTBUS
    if (!m_eventBusEnabled || !m_eventBus.IsConnected()) return;
    
    m_eventBus.PublishStreamCompleted(
        m_sessionId.load(),
        m_chunkIndex.load(),
        0, // token count (not tracked yet)
        0  // duration (not tracked yet)
    );
#endif
}

void CodexCLI::PublishStreamError(const std::string& error) {
#ifdef RAWRXD_ENABLE_CODEX_EVENTBUS
    if (!m_eventBusEnabled || !m_eventBus.IsConnected()) return;
    
    m_eventBus.PublishStreamError(
        m_sessionId.load(),
        1, // generic error code
        error
    );
#endif
}

} // namespace Codex
} // namespace RawrXD
