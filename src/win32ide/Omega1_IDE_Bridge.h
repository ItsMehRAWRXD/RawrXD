// ============================================================================
// Omega1 IDE Bridge - Connects IPC Client to Win32IDE Ghost Text
// WM_USER+0x7001 message pump integration
// ============================================================================

#pragma once
#include "Omega1_IPC_Client.h"
#include "GhostOverlay.h"
#include <windows.h>

namespace RawrXD {
namespace Omega1 {

// Custom window messages
constexpr UINT WM_OMEGA1_TOKEN = WM_USER + 0x7001;
constexpr UINT WM_OMEGA1_COMPLETE = WM_USER + 0x7002;
constexpr UINT WM_OMEGA1_ERROR = WM_USER + 0x7003;
constexpr UINT WM_OMEGA1_TELEMETRY = WM_USER + 0x7004;

// Bridge singleton - manages OMEGA-1 connection for the IDE
class IDEIntegrationBridge {
public:
    static IDEIntegrationBridge& GetInstance();

    // Initialize/shutdown
    bool Initialize(HWND hMainWindow, HWND hStatusBar);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // Connection to OMEGA-1 server
    bool ConnectToServer();
    void DisconnectFromServer();
    bool IsConnected() const;

    // Ghost text operations
    void TriggerGhostCompletion(HWND hEditor);
    void CancelGhostCompletion();
    bool IsGenerating() const;
    std::wstring GetCurrentGhostText() const;
    void AcceptGhostText();
    void RejectGhostText();

    // Status bar telemetry
    void UpdateStatusBar();
    std::wstring GetTelemetryString() const;

    // Window message handler (call from main WndProc)
    LRESULT HandleMessage(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // Periodic update (call from idle/timer)
    void OnIdle();

    // Model management
    bool LoadModel(const wchar_t* modelPath);
    void UnloadModel();
    bool IsModelLoaded() const;

    // Settings
    void SetTemperature(float temp) { m_temperature = temp; }
    void SetTopP(float topP) { m_topP = topP; }
    void SetMaxTokens(uint32_t tokens) { m_maxTokens = tokens; }

private:
    IDEIntegrationBridge() = default;
    ~IDEIntegrationBridge() = default;

    // Non-copyable
    IDEIntegrationBridge(const IDEIntegrationBridge&) = delete;
    IDEIntegrationBridge& operator=(const IDEIntegrationBridge&) = delete;

    bool m_initialized = false;
    HWND m_hMainWindow = nullptr;
    HWND m_hStatusBar = nullptr;
    HWND m_hCurrentEditor = nullptr;

    // IPC client
    IPCClient m_ipcClient;

    // Ghost text state
    std::wstring m_ghostText;
    std::atomic<bool> m_generating{false};
    uint32_t m_currentRequestId = 0;

    // Settings
    float m_temperature = 0.7f;
    float m_topP = 0.9f;
    uint32_t m_maxTokens = 256;

    // Cached telemetry
    Omega1StatusResponse m_cachedStatus{};
    std::chrono::steady_clock::time_point m_lastTelemetryUpdate;

    // Callback handlers
    void OnToken(const wchar_t* token, size_t len, bool isFinal);
    void OnComplete();
    void OnError(Omega1Status code, const wchar_t* message);
    void OnTelemetry(const Omega1StatusResponse& status);

    // Editor integration
    void PostTokenToEditor(const wchar_t* token);
    void PostCompletionToEditor();
    void PostErrorToEditor(const wchar_t* message);

    // Get context from editor
    std::wstring GetEditorContext(HWND hEditor);
};

// Helper macros for IDE integration
#define OMEGA1_BRIDGE() RawrXD::Omega1::IDEIntegrationBridge::GetInstance()

} // namespace Omega1
} // namespace RawrXD
