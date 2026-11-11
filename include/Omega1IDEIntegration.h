// Omega1IDEIntegration.h
// RawrXD Win32IDE OMEGA-1 Integration Coordinator
// Bridges editor events → IPC → ghost text rendering

#pragma once
#include "Omega1IPCClient.h"
#include "GhostTextRenderer.h"
#include "StatusBarTelemetry.h"
#include <thread>
#include <atomic>
#include <mutex>

// ─── Integration Configuration ───
struct Omega1IntegrationConfig {
    wchar_t pipeName[128];
    uint32_t completionDelayMs;      // Delay before triggering completion
    uint32_t minContextLines;        // Minimum context to send
    uint32_t maxContextLines;        // Maximum context to send
    uint32_t maxTokens;              // Default max tokens for completion
    float temperature;               // Default temperature
    float topP;                      // Default top_p
    bool enableStreaming;            // Use streaming vs single-shot
    bool stopOnNewline;              // Stop at newline for single-line

    Omega1IntegrationConfig() {
        wcscpy_s(pipeName, L"\\\\.\\pipe\\RawrXD_Omega1_v2");
        completionDelayMs = 300;     // 300ms delay
        minContextLines = 10;
        maxContextLines = 50;
        maxTokens = 64;
        temperature = 0.7f;
        topP = 0.9f;
        enableStreaming = true;
        stopOnNewline = true;
    }
};

// ─── IDE Integration Coordinator ───
class Omega1IDEIntegration {
public:
    Omega1IDEIntegration() noexcept;
    ~Omega1IDEIntegration();

    // No copy/move
    Omega1IDEIntegration(const Omega1IDEIntegration&) = delete;
    Omega1IDEIntegration& operator=(const Omega1IDEIntegration&) = delete;
    Omega1IDEIntegration(Omega1IDEIntegration&&) = delete;
    Omega1IDEIntegration& operator=(Omega1IDEIntegration&&) = delete;

    // ─── Lifecycle ───
    bool Initialize(HWND hwndEditor, const Omega1IntegrationConfig& config = {});
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized; }
    bool IsConnected() const noexcept { return m_ipc.IsConnected(); }

    // ─── Editor Event Handlers ───
    void OnEditorTextChanged(uint32_t line, uint32_t col);
    void OnEditorCursorMoved(uint32_t line, uint32_t col);
    void OnEditorKeyDown(WPARAM key);
    void OnEditorFocus();
    void OnEditorBlur();

    // ─── Ghost Text Actions ───
    bool AcceptGhostText();      // Tab key
    bool RejectGhostText();      // Escape or typing
    bool IsGhostTextVisible() const noexcept { return m_ghostText.IsVisible(); }

    // ─── Model Management ───
    bool SwitchModel(const char* modelPath, uint32_t gpuLayers = 999, bool useSecondaryGpu = false);
    
    // ─── Rendering ───
    void RenderGhostText(HDC hdc) { m_ghostText.Render(hdc); }
    void UpdateStatusBar() { UpdateTelemetry(); }

    // ─── Window Message Handling ───
    bool HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);

private:
    void WorkerThread();
    void TriggerCompletion(uint32_t line, uint32_t col);
    void UpdateTelemetry();
    std::string ExtractContext(uint32_t line, uint32_t& outStartLine);

    // Components
    Omega1IPCClient m_ipc;
    GhostTextRenderer m_ghostText;
    StatusBarTelemetry m_statusBar;
    Omega1IntegrationConfig m_config;

    // Threading
    std::thread m_workerThread;
    std::atomic<bool> m_running;
    std::atomic<bool> m_initialized;
    std::mutex m_contextMutex;

    // State
    HWND m_hwndEditor;
    uint32_t m_pendingLine;
    uint32_t m_pendingCol;
    std::atomic<bool> m_hasPendingCompletion;
    std::atomic<bool> m_isGenerating;
    
    // Editor interface callbacks (to be implemented by IDE)
    std::function<std::string(uint32_t, uint32_t)> m_getContextCallback;
    std::function<void(uint32_t, uint32_t, const std::string&)> m_insertTextCallback;
};
