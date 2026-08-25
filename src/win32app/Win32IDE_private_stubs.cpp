// ============================================================================
// Win32IDE_private_stubs.cpp - Real implementations for private Win32IDE methods
// ============================================================================

#include "Win32IDE.h"
#include "../agentic/AgentOllamaClient.h"
#include <windows.h>
#include <sstream>

void Win32IDE::HandleCopilotSend_Ollama() {
    // Fix #2: Real Ollama chat implementation for Win32IDE
    if (!m_agenticBridge) return;
    
    // Get the current prompt from the chat input
    std::string prompt = m_currentPrompt;
    if (prompt.empty()) return;
    
    // Configure Ollama client
    RawrXD::Agent::OllamaConfig cfg;
    cfg.host = "127.0.0.1";
    cfg.port = 11434;
    cfg.temperature = 0.7f;
    cfg.max_tokens = 2048;
    cfg.use_gpu = true;
    cfg.num_gpu = 99;
    
    RawrXD::Agent::AgentOllamaClient client(cfg);
    
    // Build conversation
    std::vector<RawrXD::Agent::ChatMessage> messages;
    messages.push_back({"system", "You are RawrXD IDE's AI assistant. Provide accurate, concise answers.", "", {}});
    messages.push_back({"user", prompt, "", {}});
    
    // Send async request
    auto result = client.ChatSync(messages);
    
    if (result.success) {
        OutputDebugStringA(("[Win32IDE] Ollama response: " + result.response.substr(0, 100) + "...\n").c_str());
        // Update chat panel with response
        if (m_chatPanelHwnd) {
            // Post message to update chat display
            PostMessageA(m_chatPanelHwnd, WM_USER + 100, 0, (LPARAM)_strdup(result.response.c_str()));
        }
    } else {
        OutputDebugStringA(("[Win32IDE] Ollama error: " + result.error_message + "\n").c_str());
    }
    
    m_currentPrompt.clear();
}

void Win32IDE::initializeChatPanelOllama() {
    // Fix #3: Initialize Ollama chat panel with real configuration
    OutputDebugStringA("[Win32IDE] Initializing Ollama chat panel with real config\n");
    
    // Test Ollama connection
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
        
        // Store available models for UI
        m_availableOllamaModels = models;
    } else {
        OutputDebugStringA("[Win32IDE] Ollama not available on port 11434\n");
    }
}

void Win32IDE::showSemanticIndex() {
    // Fix #4: Real semantic index display
    OutputDebugStringA("[Win32IDE] Building semantic index...\n");
    
    if (!m_codexUltimate) {
        OutputDebugStringA("[Win32IDE] CodexUltimate not initialized\n");
        return;
    }
    
    // Query semantic index status
    std::string status = m_codexUltimate->GetSemanticIndexStatus();
    OutputDebugStringA(("[Win32IDE] Semantic index status: " + status + "\n").c_str());
    
    // Show in output panel if available
    if (m_outputPanelHwnd) {
        SetWindowTextA(m_outputPanelHwnd, status.c_str());
    }
}
