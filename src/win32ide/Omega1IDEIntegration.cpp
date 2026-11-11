// Omega1IDEIntegration.cpp
// RawrXD Win32IDE OMEGA-1 Integration Coordinator
// Bridges editor events → IPC → ghost text rendering

#include "Omega1IDEIntegration.h"
#include <chrono>
#include <algorithm>

// ─── Construction / Destruction ───

Omega1IDEIntegration::Omega1IDEIntegration() noexcept
    : m_hwndEditor(nullptr)
    , m_pendingLine(0)
    , m_pendingCol(0)
    , m_hasPendingCompletion(false)
    , m_isGenerating(false)
    , m_running(false)
    , m_initialized(false)
{
}

Omega1IDEIntegration::~Omega1IDEIntegration() {
    Shutdown();
}

// ─── Lifecycle ───

bool Omega1IDEIntegration::Initialize(HWND hwndEditor, const Omega1IntegrationConfig& config) {
    if (m_initialized) return true;
    if (!hwndEditor) return false;

    m_hwndEditor = hwndEditor;
    m_config = config;

    // Initialize ghost text renderer
    HFONT hFont = (HFONT)SendMessageW(hwndEditor, WM_GETFONT, 0, 0);
    if (!m_ghostText.Initialize(hwndEditor, hFont)) {
        return false;
    }

    // Initialize status bar
    HWND hwndParent = GetParent(hwndEditor);
    if (!hwndParent) hwndParent = hwndEditor;
    if (!m_statusBar.Initialize(hwndParent, 4)) {
        return false;
    }
    m_statusBar.SetConnecting();

    // Connect to OMEGA-1 engine
    if (!m_ipc.Connect(m_config.pipeName, 10000)) {
        m_statusBar.SetDisconnected();
        return false;
    }

    // Ping to verify connection
    uint64_t latency = 0;
    if (!m_ipc.Ping(latency)) {
        m_statusBar.SetDisconnected();
        return false;
    }

    // Start worker thread
    m_running = true;
    m_workerThread = std::thread(&Omega1IDEIntegration::WorkerThread, this);

    m_initialized = true;
    UpdateTelemetry();
    return true;
}

void Omega1IDEIntegration::Shutdown() {
    if (!m_initialized) return;

    // Stop worker thread
    m_running = false;
    m_hasPendingCompletion = false;
    
    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }

    // Cancel any active stream
    if (m_ipc.IsStreaming()) {
        m_ipc.CancelStream();
    }

    // Disconnect IPC
    m_ipc.Disconnect();

    // Shutdown components
    m_ghostText.Shutdown();
    m_statusBar.Shutdown();

    m_initialized = false;
}

// ─── Editor Event Handlers ───

void Omega1IDEIntegration::OnEditorTextChanged(uint32_t line, uint32_t col) {
    if (!m_initialized) return;

    // Reject existing ghost text on any edit
    if (m_ghostText.IsVisible()) {
        RejectGhostText();
    }

    // Queue new completion
    std::lock_guard<std::mutex> lock(m_contextMutex);
    m_pendingLine = line;
    m_pendingCol = col;
    m_hasPendingCompletion = true;
}

void Omega1IDEIntegration::OnEditorCursorMoved(uint32_t line, uint32_t col) {
    if (!m_initialized) return;

    // Update ghost text position if visible
    if (m_ghostText.IsVisible()) {
        m_ghostText.UpdatePosition(line, col);
    }
}

void Omega1IDEIntegration::OnEditorKeyDown(WPARAM key) {
    if (!m_initialized) return;

    switch (key) {
        case VK_TAB:
            if (m_ghostText.IsVisible()) {
                AcceptGhostText();
            }
            break;

        case VK_ESCAPE:
            if (m_ghostText.IsVisible()) {
                RejectGhostText();
            }
            break;

        default:
            // Any other key rejects ghost text
            if (m_ghostText.IsVisible()) {
                RejectGhostText();
            }
            break;
    }
}

void Omega1IDEIntegration::OnEditorFocus() {
    if (!m_initialized) return;
    UpdateTelemetry();
}

void Omega1IDEIntegration::OnEditorBlur() {
    // Optional: pause generation or keep going
}

// ─── Ghost Text Actions ───

bool Omega1IDEIntegration::AcceptGhostText() {
    if (!m_ghostText.IsVisible()) return false;

    std::wstring text = m_ghostText.Commit();
    if (text.empty()) return false;

    // Insert text into editor (callback to IDE)
    if (m_insertTextCallback) {
        std::string utf8(text.begin(), text.end());
        m_insertTextCallback(m_ghostText.GetInsertLine(), m_ghostText.GetInsertCol(), utf8);
    }

    return true;
}

bool Omega1IDEIntegration::RejectGhostText() {
    if (!m_ghostText.IsVisible()) return false;
    m_ghostText.Reject();
    return true;
}

// ─── Model Management ───

bool Omega1IDEIntegration::SwitchModel(const char* modelPath, uint32_t gpuLayers, bool useSecondaryGpu) {
    if (!m_initialized || !m_ipc.IsConnected()) return false;

    O1ModelSwitchRequest request = {};
    strncpy_s(request.modelPath, modelPath, sizeof(request.modelPath) - 1);
    request.gpuLayers = gpuLayers;
    request.contextSize = 4096; // Default
    request.useSecondaryGpu = useSecondaryGpu ? 1 : 0;

    return m_ipc.SwitchModel(request);
}

// ─── Worker Thread ───

void Omega1IDEIntegration::WorkerThread() {
    while (m_running) {
        // Check for pending completion requests
        if (m_hasPendingCompletion) {
            // Debounce delay
            std::this_thread::sleep_for(std::chrono::milliseconds(m_config.completionDelayMs));
            
            if (!m_running) break;

            uint32_t line, col;
            {
                std::lock_guard<std::mutex> lock(m_contextMutex);
                line = m_pendingLine;
                col = m_pendingCol;
                m_hasPendingCompletion = false;
            }

            TriggerCompletion(line, col);
        }

        // Poll for stream tokens if streaming
        if (m_ipc.IsStreaming()) {
            O1StreamTokenResponse token = {};
            std::string text;
            
            if (m_ipc.TryReceiveStreamToken(token, text, 50)) {
                if (token.isFinal) {
                    m_isGenerating = false;
                } else if (!text.empty()) {
                    // Accumulate and display
                    // For now, just show final result
                }
            }
        }

        // Periodic telemetry update
        static auto lastTelemetry = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        if (now - lastTelemetry > std::chrono::milliseconds(250)) {
            UpdateTelemetry();
            lastTelemetry = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void Omega1IDEIntegration::TriggerCompletion(uint32_t line, uint32_t col) {
    if (!m_ipc.IsConnected()) return;

    // Extract context from editor
    uint32_t contextStartLine = 0;
    std::string context = ExtractContext(line, contextStartLine);
    if (context.empty()) return;

    if (m_config.enableStreaming) {
        // Streaming mode
        O1StreamRequest request = {};
        request.cursorLine = line;
        request.cursorCol = col;
        request.maxTokens = m_config.maxTokens;
        request.temperature = m_config.temperature;
        request.topP = m_config.topP;
        request.stopOnNewline = m_config.stopOnNewline ? 1 : 0;
        request.contextLinesBefore = line - contextStartLine;
        request.contextLinesAfter = 0;

        if (m_ipc.StartStream(request, context)) {
            m_isGenerating = true;
        }
    } else {
        // Single-shot mode
        O1CompletionRequest request = {};
        request.cursorLine = line;
        request.cursorCol = col;
        request.maxTokens = m_config.maxTokens;
        request.temperature = m_config.temperature;
        request.topP = m_config.topP;
        request.contextLinesBefore = line - contextStartLine;
        request.contextLinesAfter = 0;

        O1GhostTextResponse response = {};
        std::string completionText;

        if (m_ipc.RequestCompletion(request, context, response, completionText)) {
            if (!completionText.empty()) {
                m_ghostText.ShowGhostText(completionText, line, col, response.confidence);
            }
        }
    }
}

void Omega1IDEIntegration::UpdateTelemetry() {
    if (!m_ipc.IsConnected()) {
        m_statusBar.SetDisconnected();
        return;
    }

    O1StatusTelemetry telemetry = {};
    std::string modelName;

    if (m_ipc.QueryStatus(telemetry, modelName)) {
        m_statusBar.UpdateFromTelemetry(telemetry, modelName);
    }
}

std::string Omega1IDEIntegration::ExtractContext(uint32_t line, uint32_t& outStartLine) {
    // This would interface with the actual editor to get text
    // For now, return empty - IDE needs to provide callback
    if (m_getContextCallback) {
        return m_getContextCallback(line, m_config.maxContextLines);
    }
    return "";
}

// ─── Window Message Handling ───

bool Omega1IDEIntegration::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    if (m_ghostText.HandleMessage(msg, wParam, lParam)) {
        return true;
    }
    if (m_statusBar.HandleMessage(msg, wParam, lParam)) {
        return true;
    }
    return false;
}
