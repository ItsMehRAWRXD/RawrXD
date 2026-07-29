// ============================================================================
// Omega1 IDE Bridge Implementation
// Connects OMEGA-1 engine to Win32IDE ghost text and status bar
// ============================================================================

#include "Omega1_IDE_Bridge.h"
#include <chrono>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "user32.lib")

namespace RawrXD {
namespace Omega1 {

// ============================================================================
// Singleton
// ============================================================================

IDEIntegrationBridge& IDEIntegrationBridge::GetInstance() {
    static IDEIntegrationBridge instance;
    return instance;
}

// ============================================================================
// Initialization
// ============================================================================

bool IDEIntegrationBridge::Initialize(HWND hMainWindow, HWND hStatusBar) {
    if (m_initialized) return true;

    m_hMainWindow = hMainWindow;
    m_hStatusBar = hStatusBar;

    // Set up IPC callbacks
    m_ipcClient.SetTokenCallback([this](const wchar_t* token, size_t len, bool isFinal) {
        OnToken(token, len, isFinal);
    });

    m_ipcClient.SetTelemetryCallback([this](const Omega1StatusResponse& status) {
        OnTelemetry(status);
    });

    m_ipcClient.SetErrorCallback([this](Omega1Status code, const wchar_t* msg) {
        OnError(code, msg);
    });

    // Try to connect to server
    ConnectToServer();

    m_initialized = true;
    return true;
}

void IDEIntegrationBridge::Shutdown() {
    if (!m_initialized) return;

    CancelGhostCompletion();
    DisconnectFromServer();

    m_hMainWindow = nullptr;
    m_hStatusBar = nullptr;
    m_initialized = false;
}

// ============================================================================
// Connection Management
// ============================================================================

bool IDEIntegrationBridge::ConnectToServer() {
    if (m_ipcClient.IsConnected()) return true;

    if (!m_ipcClient.Connect()) {
        // Server not running - could start it here
        return false;
    }

    // Request initial status
    m_ipcClient.GetStatus();

    return true;
}

void IDEIntegrationBridge::DisconnectFromServer() {
    m_ipcClient.Disconnect();
}

bool IDEIntegrationBridge::IsConnected() const {
    return m_ipcClient.IsConnected();
}

// ============================================================================
// Ghost Text Operations
// ============================================================================

void IDEIntegrationBridge::TriggerGhostCompletion(HWND hEditor) {
    if (!m_ipcClient.IsConnected()) {
        if (!ConnectToServer()) {
            // Show error in status bar
            if (m_hStatusBar) {
                SendMessageW(m_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"[OMEGA-1] Server not connected");
            }
            return;
        }
    }

    // Cancel any existing generation
    if (m_generating) {
        CancelGhostCompletion();
    }

    m_hCurrentEditor = hEditor;
    m_ghostText.clear();
    m_generating = true;

    // Get context from editor
    std::wstring context = GetEditorContext(hEditor);

    // System prompt for code completion
    const wchar_t* systemPrompt = 
        L"You are an expert coding assistant. Complete the code based on context. "
        L"Provide only the completion, no explanations. "
        L"Match the existing code style and indentation.";

    // Send request
    m_ipcClient.RequestCompletion(
        context.c_str(),
        systemPrompt,
        m_maxTokens,
        m_temperature,
        m_topP
    );

    // Update status bar
    if (m_hStatusBar) {
        SendMessageW(m_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"[OMEGA-1] Generating...");
    }
}

void IDEIntegrationBridge::CancelGhostCompletion() {
    if (!m_generating) return;

    m_ipcClient.CancelGeneration();
    m_generating = false;
    m_ghostText.clear();

    // Clear ghost overlay if attached
    // (Would need GhostOverlay instance reference)

    if (m_hStatusBar) {
        SendMessageW(m_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"[OMEGA-1] Cancelled");
    }
}

bool IDEIntegrationBridge::IsGenerating() const {
    return m_generating;
}

std::wstring IDEIntegrationBridge::GetCurrentGhostText() const {
    return m_ghostText;
}

void IDEIntegrationBridge::AcceptGhostText() {
    if (!m_generating && m_ghostText.empty()) return;

    // Post completion message to editor
    PostCompletionToEditor();

    m_generating = false;
    m_ghostText.clear();
}

void IDEIntegrationBridge::RejectGhostText() {
    CancelGhostCompletion();
}

// ============================================================================
// Status Bar Telemetry
// ============================================================================

void IDEIntegrationBridge::UpdateStatusBar() {
    if (!m_hStatusBar) return;

    std::wstring status = GetTelemetryString();
    SendMessageW(m_hStatusBar, SB_SETTEXTW, 0, (LPARAM)status.c_str());
}

std::wstring IDEIntegrationBridge::GetTelemetryString() const {
    if (!m_ipcClient.IsConnected()) {
        return L"[OMEGA-1] Disconnected";
    }

    const auto& status = m_ipcClient.GetCachedStatus();

    std::wstringstream ss;
    ss << L"[OMEGA-1 v" << ((status.status == Omega1Status::OK) ? L"1.0" : L"?") << L"] ";

    if (status.gpuCount > 0) {
        // Find primary GPU
        int primaryIdx = -1;
        for (uint32_t i = 0; i < status.gpuCount; i++) {
            if (status.gpus[i].isPrimary) {
                primaryIdx = i;
                break;
            }
        }
        if (primaryIdx < 0) primaryIdx = 0;

        const auto& gpu = status.gpus[primaryIdx];
        ss << L"GPU: " << gpu.name << L" | ";
        
        // VRAM usage
        float vramUsedGB = gpu.vramUsed / (1024.0f * 1024.0f * 1024.0f);
        float vramTotalGB = gpu.vramTotal / (1024.0f * 1024.0f * 1024.0f);
        ss << std::fixed << std::setprecision(1);
        ss << vramUsedGB << L"/" << vramTotalGB << L"GB | ";

        // TPS
        ss << L"Prompt: " << std::setprecision(0) << gpu.tpsCurrent << L" t/s";
    }

    if (m_generating) {
        ss << L" | Generating...";
    }

    return ss.str();
}

// ============================================================================
// Window Message Handler
// ============================================================================

LRESULT IDEIntegrationBridge::HandleMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_OMEGA1_TOKEN: {
        // Token received - update ghost text
        const wchar_t* token = (const wchar_t*)lParam;
        if (token) {
            m_ghostText += token;
            // Update ghost overlay
            // (Would call GhostOverlay::SetSuggestion here)
        }
        return 0;
    }

    case WM_OMEGA1_COMPLETE: {
        // Generation complete
        m_generating = false;
        if (m_hStatusBar) {
            SendMessageW(m_hStatusBar, SB_SETTEXTW, 0, (LPARAM)L"[OMEGA-1] Ready");
        }
        return 0;
    }

    case WM_OMEGA1_ERROR: {
        // Error occurred
        m_generating = false;
        m_ghostText.clear();
        const wchar_t* errorMsg = (const wchar_t*)lParam;
        if (m_hStatusBar && errorMsg) {
            std::wstring status = L"[OMEGA-1] Error: ";
            status += errorMsg;
            SendMessageW(m_hStatusBar, SB_SETTEXTW, 0, (LPARAM)status.c_str());
        }
        return 0;
    }

    case WM_OMEGA1_TELEMETRY: {
        // Telemetry update
        UpdateStatusBar();
        return 0;
    }
    }

    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ============================================================================
// Idle Processing
// ============================================================================

void IDEIntegrationBridge::OnIdle() {
    // Poll IPC client for new data
    m_ipcClient.Poll();

    // Update status bar periodically (every 500ms)
    static auto lastUpdate = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    if (now - lastUpdate > std::chrono::milliseconds(500)) {
        UpdateStatusBar();
        lastUpdate = now;
    }
}

// ============================================================================
// Model Management
// ============================================================================

bool IDEIntegrationBridge::LoadModel(const wchar_t* modelPath) {
    if (!m_ipcClient.IsConnected()) {
        return false;
    }
    return m_ipcClient.LoadModel(modelPath);
}

void IDEIntegrationBridge::UnloadModel() {
    if (!m_ipcClient.IsConnected()) {
        return;
    }
    m_ipcClient.UnloadModel();
}

bool IDEIntegrationBridge::IsModelLoaded() const {
    const auto& status = m_ipcClient.GetCachedStatus();
    return status.status == Omega1Status::OK && status.modelName[0] != L'\0';
}

// ============================================================================
// Callback Handlers
// ============================================================================

void IDEIntegrationBridge::OnToken(const wchar_t* token, size_t len, bool isFinal) {
    if (len > 0) {
        // Post to main window for thread safety
        std::wstring* tokenCopy = new std::wstring(token, len);
        PostMessageW(m_hMainWindow, WM_OMEGA1_TOKEN, 0, (LPARAM)tokenCopy->data());
        // Note: Memory leak here - should use proper marshaling
        // In production, use a thread-safe queue
    }

    if (isFinal) {
        PostMessageW(m_hMainWindow, WM_OMEGA1_COMPLETE, 0, 0);
    }
}

void IDEIntegrationBridge::OnComplete() {
    m_generating = false;
    PostMessageW(m_hMainWindow, WM_OMEGA1_COMPLETE, 0, 0);
}

void IDEIntegrationBridge::OnError(Omega1Status code, const wchar_t* message) {
    m_generating = false;
    m_ghostText.clear();
    PostMessageW(m_hMainWindow, WM_OMEGA1_ERROR, (WPARAM)code, (LPARAM)message);
}

void IDEIntegrationBridge::OnTelemetry(const Omega1StatusResponse& status) {
    m_cachedStatus = status;
    PostMessageW(m_hMainWindow, WM_OMEGA1_TELEMETRY, 0, 0);
}

// ============================================================================
// Editor Integration Helpers
// ============================================================================

std::wstring IDEIntegrationBridge::GetEditorContext(HWND hEditor) {
    // Get text from editor window
    // This would integrate with the actual editor control (Scintilla or custom)
    
    // Placeholder implementation
    int textLen = GetWindowTextLengthW(hEditor);
    if (textLen > 0) {
        std::wstring text;
        text.resize(textLen + 1);
        GetWindowTextW(hEditor, &text[0], textLen + 1);
        text.resize(textLen);
        return text;
    }

    return L"";
}

void IDEIntegrationBridge::PostTokenToEditor(const wchar_t* token) {
    // Update ghost overlay with new token
    // Would integrate with GhostOverlay class
}

void IDEIntegrationBridge::PostCompletionToEditor() {
    // Insert ghost text into editor
    if (m_hCurrentEditor && !m_ghostText.empty()) {
        // Send EM_REPLACESEL or similar
        SendMessageW(m_hCurrentEditor, EM_REPLACESEL, TRUE, (LPARAM)m_ghostText.c_str());
    }
}

void IDEIntegrationBridge::PostErrorToEditor(const wchar_t* message) {
    // Show error message
    if (m_hStatusBar) {
        std::wstring status = L"[OMEGA-1] Error: ";
        status += message;
        SendMessageW(m_hStatusBar, SB_SETTEXTW, 0, (LPARAM)status.c_str());
    }
}

} // namespace Omega1
} // namespace RawrXD
