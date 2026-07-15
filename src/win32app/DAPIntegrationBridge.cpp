//=============================================================================
// RawrXD DAP Integration Bridge Implementation
// Connects DapService to Win32IDE's UI and DAP server
//=============================================================================
#include "DAPIntegrationBridge.hpp"
#include <windows.h>
#include <assert.h>

namespace RawrXD {
namespace Win32 {

//=============================================================================
// Window Messages for Debug Events
//=============================================================================

// Custom messages for debug event notifications
#define WM_USER_DEBUG_EVENT     (WM_USER + 0x800)
#define WM_USER_DEBUG_STARTED   (WM_USER + 0x801)
#define WM_USER_DEBUG_STOPPED   (WM_USER + 0x802)
#define WM_USER_DEBUG_PAUSED    (WM_USER + 0x803)
#define WM_USER_DEBUG_CONTINUED (WM_USER + 0x804)
#define WM_USER_STACK_RECEIVED  (WM_USER + 0x805)
#define WM_USER_VARS_RECEIVED   (WM_USER + 0x806)

// Debug event types passed in wParam
enum class DebugEventType_Win32 {
    None = 0,
    StateChanged,
    Stopped,
    Continued,
    StackTrace,
    Variables,
    Output,
    Error
};

//=============================================================================
// Global Bridge Instance
//=============================================================================

static DAPIntegrationBridge* g_dapBridge = nullptr;

DAPIntegrationBridge* GetDAPBridge() {
    return g_dapBridge;
}

void SetDAPBridge(DAPIntegrationBridge* bridge) {
    g_dapBridge = bridge;
}

//=============================================================================
// Constructor / Destructor
//=============================================================================

DAPIntegrationBridge::DAPIntegrationBridge(Win32IDE* ide, Win32IDE_DAPServer* server)
    : m_ide(ide)
    , m_server(server)
    , m_service(&Debug::DapService::instance())
{
}

DAPIntegrationBridge::~DAPIntegrationBridge() {
    Shutdown();
}

//=============================================================================
// Initialization
//=============================================================================

bool DAPIntegrationBridge::Initialize() {
    if (!m_ide || !m_service) return false;
    
    // Setup callbacks
    Debug::DapService::Callbacks callbacks;
    callbacks.onStateChanged = [this](Debug::DapState oldState, Debug::DapState newState) {
        this->OnStateChanged(oldState, newState);
    };
    callbacks.onStopped = [this](const std::string& reason, uint32_t threadId, const std::string& desc) {
        this->OnStopped(reason, threadId, desc);
    };
    callbacks.onContinued = [this](uint32_t threadId) {
        this->OnContinued(threadId);
    };
    callbacks.onStackTraceReceived = [this](const std::vector<Debug::StackFrame>& frames) {
        this->OnStackTraceReceived(frames);
    };
    callbacks.onVariablesReceived = [this](int ref, const std::vector<Debug::Variable>& vars) {
        this->OnVariablesReceived(ref, vars);
    };
    callbacks.onOutput = [this](Debug::OutputChannel ch, const std::string& data) {
        this->OnOutput(ch, data);
    };
    callbacks.onError = [this](const std::string& error, bool fatal) {
        this->OnError(error, fatal);
    };
    
    m_service->setCallbacks(callbacks);
    
    return true;
}

void DAPIntegrationBridge::Shutdown() {
    if (m_service) {
        m_service->shutdown();
    }
}

//=============================================================================
// Debug Session Control
//=============================================================================

bool DAPIntegrationBridge::IsDebugging() const {
    return m_service && m_service->state() != Debug::DapState::Disconnected;
}

Debug::DapState DAPIntegrationBridge::GetState() const {
    if (!m_service) return Debug::DapState::Disconnected;
    return m_service->state();
}

bool DAPIntegrationBridge::StartDebugging(const LaunchConfig& config) {
    if (!m_service) return false;
    
    Debug::LaunchConfig dapConfig;
    dapConfig.program = std::string(config.program.begin(), config.program.end());
    dapConfig.workingDirectory = std::string(config.workingDirectory.begin(), config.workingDirectory.end());
    for (const auto& arg : config.args) {
        dapConfig.args.push_back(std::string(arg.begin(), arg.end()));
    }
    dapConfig.stopOnEntry = config.stopOnEntry;
    
    auto result = m_service->initialize(dapConfig);
    if (!result.success) {
        return false;
    }
    
    result = m_service->launch();
    return result.success;
}

bool DAPIntegrationBridge::AttachToProcess(DWORD processId) {
    if (!m_service) return false;
    auto result = m_service->attach(processId);
    return result.success;
}

void DAPIntegrationBridge::StopDebugging() {
    if (!m_service) return;
    m_service->terminate();
    m_service->shutdown();
}

//=============================================================================
// Execution Control
//=============================================================================

void DAPIntegrationBridge::Continue() {
    if (!m_service) return;
    m_service->continueExecution();
}

void DAPIntegrationBridge::Pause() {
    if (!m_service) return;
    m_service->pause();
}

void DAPIntegrationBridge::StepInto() {
    if (!m_service) return;
    m_service->stepInto();
}

void DAPIntegrationBridge::StepOver() {
    if (!m_service) return;
    m_service->stepOver();
}

void DAPIntegrationBridge::StepOut() {
    if (!m_service) return;
    m_service->stepOut();
}

//=============================================================================
// Breakpoint Management
//=============================================================================

void DAPIntegrationBridge::ToggleBreakpoint(const std::wstring& file, int line) {
    if (!m_service) return;
    
    std::string filePath(file.begin(), file.end());
    // Note: DapService doesn't have direct toggle, we'd need to track state
    // For now, just set breakpoint
    m_service->setBreakpoint(filePath, line);
}

void DAPIntegrationBridge::ClearAllBreakpoints() {
    if (!m_service) return;
    // Would need to iterate and remove all
}

//=============================================================================
// Stack & Variables
//=============================================================================

const std::vector<Debug::StackFrame>& DAPIntegrationBridge::GetStackTrace() const {
    // Return cached stack trace
    static std::vector<Debug::StackFrame> empty;
    return empty;  // TODO: cache from callback
}

void DAPIntegrationBridge::SelectFrame(int frameId) {
    if (!m_service) return;
    // Request scopes/variables for this frame
}

void DAPIntegrationBridge::RequestVariables(int variablesReference) {
    if (!m_service) return;
    // m_service->requestVariables(variablesReference);
}

const std::vector<Debug::Variable>& DAPIntegrationBridge::GetVariables() const {
    static std::vector<Debug::Variable> empty;
    return empty;  // TODO: cache from callback
}

//=============================================================================
// Callback Handlers (Called from DapService thread)
//=============================================================================

void DAPIntegrationBridge::OnStateChanged(Debug::DapState oldState, Debug::DapState newState) {
    // Marshal to UI thread via PostMessage
    if (m_ide && IsWindow((HWND)m_ide)) {
        PostMessage((HWND)m_ide, WM_USER_DEBUG_EVENT, 
            (WPARAM)DebugEventType_Win32::StateChanged, 
            (LPARAM)newState);
    }
}

void DAPIntegrationBridge::OnStopped(const std::string& reason, uint32_t threadId, const std::string& description) {
    if (m_ide && IsWindow((HWND)m_ide)) {
        PostMessage((HWND)m_ide, WM_USER_DEBUG_PAUSED, threadId, 0);
    }
    
    // Request stack trace
    if (m_service) {
        m_service->requestStackTrace(threadId);
    }
}

void DAPIntegrationBridge::OnContinued(uint32_t threadId) {
    if (m_ide && IsWindow((HWND)m_ide)) {
        PostMessage((HWND)m_ide, WM_USER_DEBUG_CONTINUED, threadId, 0);
    }
}

void DAPIntegrationBridge::OnStackTraceReceived(const std::vector<Debug::StackFrame>& frames) {
    // Cache and notify UI
    if (m_ide && IsWindow((HWND)m_ide)) {
        PostMessage((HWND)m_ide, WM_USER_STACK_RECEIVED, frames.size(), 0);
    }
}

void DAPIntegrationBridge::OnVariablesReceived(int reference, const std::vector<Debug::Variable>& vars) {
    if (m_ide && IsWindow((HWND)m_ide)) {
        PostMessage((HWND)m_ide, WM_USER_VARS_RECEIVED, reference, vars.size());
    }
}

void DAPIntegrationBridge::OnOutput(Debug::OutputChannel channel, const std::string& data) {
    // Log to debug output panel
    OutputDebugStringA(data.c_str());
}

void DAPIntegrationBridge::OnError(const std::string& error, bool fatal) {
    // Show error message
    MessageBoxA((HWND)m_ide, error.c_str(), fatal ? "Debug Fatal Error" : "Debug Error", MB_OK | (fatal ? MB_ICONERROR : MB_ICONWARNING));
}

//=============================================================================
// UI Update Helpers (Called from UI thread)
//=============================================================================

void DAPIntegrationBridge::UpdateCallStackPanel() {
    // TODO: Update Win32IDE's call stack panel
}

void DAPIntegrationBridge::UpdateVariablesPanel() {
    // TODO: Update Win32IDE's variables panel
}

void DAPIntegrationBridge::UpdateDebugToolbar() {
    // TODO: Enable/disable buttons based on state
}

void DAPIntegrationBridge::ShowCurrentLine() {
    // TODO: Highlight current execution line in editor
}

void DAPIntegrationBridge::ClearDebugUI() {
    // TODO: Clear all debug panels
}

} // namespace Win32
} // namespace RawrXD
