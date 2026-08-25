// ============================================================================
// Win32IDE_private_stubs.cpp - Stub implementations for private Win32IDE methods
// ============================================================================

#include "Win32IDE.h"
#include "../agentic/AgentOllamaClient.h"
#include <windows.h>
#include <sstream>

void Win32IDE::HandleCopilotSend_Ollama() {
    if (!m_agenticBridge) return;
    
    // Read prompt from Copilot chat input control
    char promptBuf[4096] = {};
    if (m_hwndCopilotChatInput) {
        GetWindowTextA(m_hwndCopilotChatInput, promptBuf, sizeof(promptBuf));
    }
    std::string prompt = promptBuf;
    if (prompt.empty()) return;
    
    RawrXD::Agent::OllamaConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 11434;
    cfg.temperature = 0.7f;
    cfg.max_tokens = 2048;
    cfg.use_gpu = true;
    cfg.num_gpu = 99;
    
    RawrXD::Agent::AgentOllamaClient client(cfg);
    std::vector<RawrXD::Agent::ChatMessage> messages;
    messages.push_back({"system", "You are RawrXD IDE's AI assistant.", "", {}});
    messages.push_back({"user", prompt, "", {}});
    
    auto result = client.ChatSync(messages);
    
    if (result.success) {
        OutputDebugStringA(("[Win32IDE] Ollama response: " + result.response.substr(0, 100) + "...\n").c_str());
        if (m_hwndCopilotChatOutput) {
            appendText(m_hwndCopilotChatOutput, result.response + "\n");
        }
    } else {
        OutputDebugStringA(("[Win32IDE] Ollama error: " + result.error_message + "\n").c_str());
    }
    
    if (m_hwndCopilotChatInput) SetWindowTextA(m_hwndCopilotChatInput, "");
}

void Win32IDE::initializeChatPanelOllama() {
    OutputDebugStringA("[Win32IDE] Initializing Ollama chat panel with real config\n");
    
    RawrXD::Agent::OllamaConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 11434;
    cfg.timeout_ms = 5000;
    
    RawrXD::Agent::AgentOllamaClient client(cfg);
    bool connected = client.TestConnection();
    
    if (connected) {
        auto models = client.ListModels();
        std::ostringstream oss;
        oss << "[Win32IDE] Ollama connected. " << models.size() << " models available.\n";
        OutputDebugStringA(oss.str().c_str());
        m_availableModels = models;
    } else {
        OutputDebugStringA("[Win32IDE] Ollama not available on port 11434\n");
    }
}

void Win32IDE::showSemanticIndex() {
    OutputDebugStringA("[Win32IDE] Building semantic index...\n");
    
    if (!m_codexUltimate) {
        OutputDebugStringA("[Win32IDE] CodexUltimate not initialized\n");
        return;
    }
    
    // CodexUltimate does not expose GetSemanticIndexStatus; stub it out
    std::string status = "Semantic index: not implemented in CodexUltimate";
    OutputDebugStringA(("[Win32IDE] Semantic index status: " + status + "\n").c_str());
    
    if (m_hwndOutputPanel) {
        SetWindowTextA(m_hwndOutputPanel, status.c_str());
    }
}
