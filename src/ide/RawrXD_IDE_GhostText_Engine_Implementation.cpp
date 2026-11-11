// ============================================================================
// RawrXD_IDE_GhostText_Engine_Implementation.cpp
// Ghost Text / Inline Completion Engine - Implementation
// ============================================================================

#include "RawrXD_IDE_GhostText_Engine.hpp"
#include "SovereignBridge.hpp"
#include "SovereignSharedMemoryBridge.hpp"
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

// GhostResult structure for async message passing
struct GhostResult {
    std::string text;
    int line;
    int col;
    float confidence;
};

// Performance telemetry logger
class GhostTelemetry {
public:
    static GhostTelemetry& Instance() {
        static GhostTelemetry instance;
        return instance;
    }

    void LogEvent(const std::string& event, double latencyMs, int tokens = 0, float confidence = 0.0f, const char* bridgeMode = nullptr) {
        std::ofstream log("ghost_performance.log", std::ios::app);
        if (log.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            log << "[" << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S") << "] "
                << event << " | Latency: " << std::fixed << std::setprecision(2) << latencyMs << "ms"
                << " | Tokens: " << tokens
                << " | Confidence: " << std::setprecision(3) << confidence;
            if (bridgeMode) {
                log << " | Bridge: " << bridgeMode;
            }
            log << std::endl;
        }
    }

    void LogInferenceStart(const std::string& model) {
        m_inferenceStart = GetTickCount();
        m_modelName = model;
    }

    void LogInferenceComplete(int tokensGenerated, float confidence, const char* bridgeMode = nullptr) {
        DWORD latency = GetTickCount() - m_inferenceStart;
        LogEvent("INFERENCE_COMPLETE", latency, tokensGenerated, confidence, bridgeMode);
    }

    void LogGhostShown(const char* bridgeMode = nullptr) {
        m_ghostShownTime = GetTickCount();
        LogEvent("GHOST_SHOWN", m_ghostShownTime - m_inferenceStart, 0, 0.0f, bridgeMode);
    }

    void LogAcceptance(bool accepted, const std::string& method) {
        LogEvent(accepted ? "ACCEPTED_" + method : "DISMISSED", 0);
    }
    
    // Log end-to-end latency: keystroke to ghost text visible
    void LogEndToEndLatency(double latencyMs, const char* bridgeMode, int tokens, float confidence) {
        std::ofstream log("ghost_performance.log", std::ios::app);
        if (log.is_open()) {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            log << "[" << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S") << "] "
                << "E2E_LATENCY | Total: " << std::fixed << std::setprecision(2) << latencyMs << "ms"
                << " | Bridge: " << (bridgeMode ? bridgeMode : "unknown")
                << " | Tokens: " << tokens
                << " | Confidence: " << std::setprecision(3) << confidence
                << std::endl;
        }
    }

private:
    GhostTelemetry() = default;
    DWORD m_inferenceStart = 0;
    DWORD m_ghostShownTime = 0;
    std::string m_modelName;
};

GhostTextEngine::GhostTextEngine(HWND hwndEditor)
    : m_hwnd(hwndEditor), m_active(false), m_lastRequest(0), m_bridge(nullptr), m_shmBridge(nullptr), m_useSharedMemory(false) {
}

GhostTextEngine::~GhostTextEngine() {
    Shutdown();
}

bool GhostTextEngine::Initialize() {
    OutputDebugStringA("[SovereignBridge] Initializing...\n");
    
    // Try shared memory bridge first (higher performance)
    m_shmBridge = new RawrXD::IDE::SovereignSharedMemoryBridge();
    
    if (m_shmBridge->AttachToRuntime("RawrXD_SharedMem_Alpha")) {
        m_useSharedMemory = true;
        OutputDebugStringA("[SovereignBridge] Shared memory: CONNECTED\n");
        OutputDebugStringA("[SovereignBridge] Mode: Zero-copy IPC\n");
        
        // Send initial heartbeat to verify connection
        if (m_shmBridge->SendHeartbeat(2000)) {
            OutputDebugStringA("[GhostTextEngine] Runtime heartbeat confirmed\n");
            return true;
        } else {
            OutputDebugStringA("[GhostTextEngine] Shared memory heartbeat failed, falling back\n");
            m_shmBridge->Detach();
            delete m_shmBridge;
            m_shmBridge = nullptr;
            m_useSharedMemory = false;
        }
    } else {
        OutputDebugStringA("[SovereignBridge] Shared memory unavailable\n");
        delete m_shmBridge;
        m_shmBridge = nullptr;
    }
    
    // Fall back to process-based bridge
    m_bridge = new RawrXD::IDE::SovereignBridge();

    if (!m_bridge->IsRuntimeAvailable()) {
        OutputDebugStringA("[SovereignBridge] Process bridge unavailable\n");
        OutputDebugStringA("[GhostTextEngine] Sovereign runtime not available\n");
        return false;
    }

    OutputDebugStringA("[SovereignBridge] Mode: Process bridge\n");
    OutputDebugStringA("[GhostTextEngine] Initialized via process bridge\n");
    return true;
}

void GhostTextEngine::Shutdown() {
    if (m_shmBridge) {
        m_shmBridge->Detach();
        delete m_shmBridge;
        m_shmBridge = nullptr;
    }
    if (m_bridge) {
        delete m_bridge;
        m_bridge = nullptr;
    }
    m_active = false;
    m_useSharedMemory = false;
}

bool GhostTextEngine::IsAvailable() const {
    if (m_useSharedMemory && m_shmBridge) {
        return m_shmBridge->IsConnected();
    }
    return m_bridge != nullptr && m_bridge->IsRuntimeAvailable();
}

void GhostTextEngine::OnTextChanged(const char* buffer, int cursorLine, int cursorCol) {
    // Debounce: don't request on every keystroke
    DWORD now = GetTickCount();
    if (now - m_lastRequest < 150) return; // 150ms debounce
    m_lastRequest = now;

    // Extract context (previous 5 lines + current line prefix)
    std::string context = ExtractContext(buffer, cursorLine, cursorCol);

    // Async request to inference engine
    RequestSuggestion(context, cursorLine, cursorCol);
}

void GhostTextEngine::OnSuggestionReceived(const std::string& text, int line, int col, float confidence) {
    if (confidence < 0.3f) { // Threshold for showing
        HideSuggestion();
        return;
    }

    m_current.text = text;
    m_current.triggerLine = line;
    m_current.triggerCol = col;
    m_current.isMultiLine = (text.find('\n') != std::string::npos);
    m_current.timestamp = GetTickCount();
    m_current.confidence = confidence;
    m_current.visible = true;
    m_active = true;

    // Log ghost text shown with bridge mode
    const char* bridgeMode = m_useSharedMemory ? "Zero-copy IPC" : "Process bridge";
    GhostTelemetry::Instance().LogGhostShown(bridgeMode);

    // Invalidate editor region to trigger paint
    InvalidateGhostRegion();
}

bool GhostTextEngine::AcceptSuggestion(std::string& outText) {
    if (!m_active || !m_current.visible) return false;
    outText = m_current.text;
    GhostTelemetry::Instance().LogAcceptance(true, "TAB");
    HideSuggestion();
    return true;
}

bool GhostTextEngine::AcceptPartial(std::string& outText) {
    if (!m_active || !m_current.visible) return false;

    // Find next word boundary
    size_t pos = 0;
    while (pos < m_current.text.size() && m_current.text[pos] == ' ') ++pos;
    while (pos < m_current.text.size() && m_current.text[pos] != ' ' && m_current.text[pos] != '\n') ++pos;

    outText = m_current.text.substr(0, pos);
    m_current.text = m_current.text.substr(pos);
    m_current.triggerCol += (int)outText.size(); // Adjust for partial

    GhostTelemetry::Instance().LogAcceptance(true, "CTRL_RIGHT");

    if (m_current.text.empty()) HideSuggestion();
    else InvalidateGhostRegion();

    return true;
}

void GhostTextEngine::HideSuggestion() {
    if (!m_active) return;
    m_active = false;
    m_current.visible = false;
    InvalidateGhostRegion();
}

void GhostTextEngine::LogDismissal() {
    GhostTelemetry::Instance().LogAcceptance(false, "ESC");
}

void GhostTextEngine::CheckDismiss(const char* currentLine, int cursorCol) {
    if (!m_active) return;

    // If cursor moved before trigger point, dismiss
    if (cursorCol < m_current.triggerCol) {
        HideSuggestion();
        return;
    }

    // If typed text doesn't match suggestion prefix, dismiss
    int prefixLen = cursorCol - m_current.triggerCol;
    if (prefixLen > 0 && prefixLen <= (int)m_current.text.size()) {
        std::string typed(currentLine + m_current.triggerCol, prefixLen);
        std::string expected = m_current.text.substr(0, prefixLen);
        if (typed != expected) {
            HideSuggestion();
        }
    }
}

void GhostTextEngine::PaintGhostText(HDC hdc, const RECT& editorRect,
                                      int lineHeight, int charWidth,
                                      int scrollX, int scrollY,
                                      int cursorScreenX, int cursorScreenY) {
    if (!m_active || !m_current.visible) return;

    // Calculate ghost text position (starts at cursor)
    int x = cursorScreenX;
    int y = cursorScreenY;

    // Set ghost text styling — dimmed gray
    COLORREF ghostColor = RGB(128, 128, 128); // Medium gray
    COLORREF oldColor = SetTextColor(hdc, ghostColor);

    // Use italic font for ghost text
    HFONT hFont = (HFONT)GetCurrentObject(hdc, OBJ_FONT);
    LOGFONTA lf = {};
    GetObjectA(hFont, sizeof(lf), &lf);
    lf.lfItalic = TRUE;
    HFONT hGhostFont = CreateFontIndirectA(&lf);
    HFONT hOldFont = (HFONT)SelectObject(hdc, hGhostFont);

    // Set background mode transparent
    int oldBkMode = SetBkMode(hdc, TRANSPARENT);

    // Draw each line of suggestion
    const char* p = m_current.text.c_str();
    while (*p) {
        const char* lineEnd = strchr(p, '\n');
        std::string line;
        if (lineEnd) {
            line = std::string(p, lineEnd - p);
            p = lineEnd + 1;
        } else {
            line = p;
            p += strlen(p);
        }

        // Clip to editor bounds
        RECT clipRect = editorRect;
        clipRect.left = x;
        clipRect.top = y;
        clipRect.bottom = y + lineHeight;

        DrawTextA(hdc, line.c_str(), (int)line.size(), &clipRect,
                  DT_LEFT | DT_NOPREFIX | DT_SINGLELINE);

        y += lineHeight;
    }

    // Restore state
    SetBkMode(hdc, oldBkMode);
    SelectObject(hdc, hOldFont);
    DeleteObject(hGhostFont);
    SetTextColor(hdc, oldColor);
}

bool GhostTextEngine::HandleKey(WPARAM key) {
    switch (key) {
        case VK_TAB: {
            // Try to accept ghost text first
            std::string accepted;
            if (AcceptSuggestion(accepted)) {
                // Insert accepted text at cursor
                std::wstring waccepted(accepted.begin(), accepted.end());
                SendMessageW(m_hwnd, EM_REPLACESEL, TRUE, (LPARAM)waccepted.c_str());
                return true; // Handled
            }
            break;
        }
        case VK_ESCAPE: {
            if (m_active) {
                LogDismissal();
                HideSuggestion();
                return true;
            }
            break;
        }
        case VK_RIGHT: {
            if (GetAsyncKeyState(VK_CONTROL) < 0) { // Ctrl+Right
                std::string accepted;
                if (AcceptPartial(accepted)) {
                    std::wstring waccepted(accepted.begin(), accepted.end());
                    SendMessageW(m_hwnd, EM_REPLACESEL, TRUE, (LPARAM)waccepted.c_str());
                    return true;
                }
            }
            break;
        }
    }
    return false; // Not handled
}

void GhostTextEngine::HandleInferenceResult(const std::string& text, int line, int col, float confidence) {
    OnSuggestionReceived(text, line, col, confidence);
}

std::string GhostTextEngine::ExtractContext(const char* buffer, int cursorLine, int cursorCol) {
    // Simple context extraction — last 5 lines + current line prefix
    std::string context;
    const char* p = buffer;
    int line = 0;

    while (*p && line < cursorLine - 5) {
        if (*p == '\n') ++line;
        ++p;
    }

    // Copy up to cursor position
    const char* cursorPos = p;
    for (int i = 0; i < cursorCol && *cursorPos && *cursorPos != '\n'; ++i) {
        ++cursorPos;
    }

    context = std::string(p, cursorPos - p);
    return context;
}

// Request sequence counter for cancellation tracking
static std::atomic<uint64_t> g_requestSequence(0);

void GhostTextEngine::RequestSuggestion(const std::string& context, int line, int col) {
    // Prevent multiple concurrent requests
    if (m_requestInFlight.exchange(true)) {
        // Cancel previous request by incrementing sequence
        // (runtime will check sequence number)
        OutputDebugStringA("[GhostTextEngine] Cancelling previous request\n");
    }

    // Check if bridge is available
    if (m_useSharedMemory) {
        if (!m_shmBridge || !m_shmBridge->IsConnected()) {
            m_requestInFlight = false;
            return;
        }
    } else {
        if (!m_bridge || !m_bridge->IsRuntimeAvailable()) {
            m_requestInFlight = false;
            return;
        }
    }

    // Log inference start for telemetry
    GhostTelemetry::Instance().LogInferenceStart("phi3-mini");
    DWORD requestStart = GetTickCount();
    uint64_t requestId = ++g_requestSequence;
    const char* bridgeMode = m_useSharedMemory ? "Zero-copy IPC" : "Process bridge";

    // Launch async inference request
    std::thread inferenceThread([this, context, line, col, requestStart, requestId, bridgeMode]() {
        std::string completion;
        float confidence = 0.0f;
        bool success = false;

        if (m_useSharedMemory && m_shmBridge) {
            // Use high-performance shared memory bridge
            std::string fimPrompt = "<PRE> " + context + " <SUF> <MID>";
            
            success = m_shmBridge->RequestCompletion(
                fimPrompt,
                "models/phi3-mini.gguf",
                64,     // maxTokens
                0.7f,   // temperature
                completion,
                confidence,
                5000    // timeoutMs
            );
            
            if (!success) {
                OutputDebugStringA("[GhostTextEngine] Shared memory request failed: ");
                OutputDebugStringA(m_shmBridge->GetLastError());
                OutputDebugStringA("\n");
            }
        } else if (m_bridge) {
            // Fall back to process-based bridge
            RawrXD::IDE::SovereignConfig config;
            config.maxTokens = 64;
            config.autonomous = false;
            config.validate = false;
            config.timeoutMs = 5000;

            std::string fimPrompt = "<PRE> " + context + " <SUF> <MID>";
            RawrXD::IDE::SovereignResult result = m_bridge->Validate(fimPrompt, config);

            if (result.IsSuccess() && !result.output.empty()) {
                completion = result.output;
                
                // Calculate confidence
                confidence = 0.5f;
                if (completion.length() > 0 && completion.length() < 256) {
                    confidence = 0.7f;
                }
                if (result.exitCode == 0) {
                    confidence += 0.2f;
                }
                success = true;
            }
        }

        if (success && !completion.empty()) {
            // Clean up the completion
            while (!completion.empty() &&
                   (completion.back() == '\n' || completion.back() == '\r')) {
                completion.pop_back();
            }

            // Log completion metrics with bridge mode
            DWORD latency = GetTickCount() - requestStart;
            int tokens = completion.length() / 4;
            GhostTelemetry::Instance().LogInferenceComplete(tokens, confidence, bridgeMode);

            // Post result back to UI thread
            GhostResult* gr = new GhostResult{completion, line, col, confidence};
            PostMessage(m_hwnd, WM_GHOST_SUGGESTION, 0, (LPARAM)gr);
        }

        m_requestInFlight = false;
    });

    inferenceThread.detach();
}

void GhostTextEngine::InvalidateGhostRegion() {
    if (!m_hwnd) return;
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    InvalidateRect(m_hwnd, &rc, FALSE);
}
