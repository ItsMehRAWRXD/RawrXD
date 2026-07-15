//=============================================================================
// RawrXD Status Bar Git Monitor Implementation
// Background thread updates git status without blocking UI
//=============================================================================
#include "StatusBarGitMonitor.hpp"
#include <process.h>

namespace RawrXD {
namespace Win32 {

//=============================================================================
// Constructor / Destructor
//=============================================================================

StatusBarGitMonitor::StatusBarGitMonitor() {
    InitializeCriticalSection(&m_statusCs);
}

StatusBarGitMonitor::~StatusBarGitMonitor() {
    Shutdown();
    DeleteCriticalSection(&m_statusCs);
}

//=============================================================================
// Initialization
//=============================================================================

bool StatusBarGitMonitor::Initialize(HWND hwndNotify, UINT msgNotify) {
    if (!IsWindow(hwndNotify)) return false;
    
    m_hwndNotify = hwndNotify;
    m_msgNotify = msgNotify;
    
    // Create events for thread control
    m_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    m_hUpdateEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    
    if (!m_hStopEvent || !m_hUpdateEvent) {
        return false;
    }
    
    return true;
}

void StatusBarGitMonitor::Shutdown() {
    StopMonitoring();
    
    if (m_hStopEvent) {
        CloseHandle(m_hStopEvent);
        m_hStopEvent = NULL;
    }
    if (m_hUpdateEvent) {
        CloseHandle(m_hUpdateEvent);
        m_hUpdateEvent = NULL;
    }
    
    m_hwndNotify = NULL;
}

//=============================================================================
// Monitoring Control
//=============================================================================

bool StatusBarGitMonitor::StartMonitoring(DWORD intervalMs) {
    if (m_running) return true;
    if (!m_hStopEvent || !m_hUpdateEvent) return false;
    
    m_intervalMs = intervalMs;
    m_running = true;
    
    // Reset stop event
    ResetEvent(m_hStopEvent);
    
    // Create monitor thread
    m_hMonitorThread = CreateThread(
        NULL,           // Default security
        0,              // Default stack size
        MonitorThreadProc,
        this,           // Parameter
        0,              // Creation flags
        NULL            // Thread ID
    );
    
    if (!m_hMonitorThread) {
        m_running = false;
        return false;
    }
    
    return true;
}

void StatusBarGitMonitor::StopMonitoring() {
    if (!m_running) return;
    
    // Signal thread to stop
    m_running = false;
    SetEvent(m_hStopEvent);
    SetEvent(m_hUpdateEvent);  // Wake up if waiting
    
    // Wait for thread to finish (with timeout)
    if (m_hMonitorThread) {
        WaitForSingleObject(m_hMonitorThread, 5000);
        CloseHandle(m_hMonitorThread);
        m_hMonitorThread = NULL;
    }
}

void StatusBarGitMonitor::RequestImmediateUpdate() {
    if (!m_running) return;
    SetEvent(m_hUpdateEvent);
}

//=============================================================================
// Status Access
//=============================================================================

StatusBarGitMonitor::GitStatus StatusBarGitMonitor::GetCurrentStatus() const {
    EnterCriticalSection(&m_statusCs);
    GitStatus status = m_currentStatus;
    LeaveCriticalSection(&m_statusCs);
    return status;
}

bool StatusBarGitMonitor::IsUpdatePending() const {
    return m_updatePending.load();
}

//=============================================================================
// Background Thread
//=============================================================================

DWORD WINAPI StatusBarGitMonitor::MonitorThreadProc(LPVOID param) {
    StatusBarGitMonitor* self = static_cast<StatusBarGitMonitor*>(param);
    self->MonitorLoop();
    return 0;
}

void StatusBarGitMonitor::MonitorLoop() {
    HANDLE waitHandles[] = { m_hStopEvent, m_hUpdateEvent };
    
    // Do initial update immediately
    UpdateStatus();
    NotifyUI();
    
    while (m_running) {
        // Wait for stop signal, update request, or timeout
        DWORD waitResult = WaitForMultipleObjects(
            2,                          // Number of handles
            waitHandles,                // Array of handles
            FALSE,                      // Wait for any
            m_intervalMs                // Timeout
        );
        
        if (waitResult == WAIT_OBJECT_0) {
            // Stop event signaled
            break;
        }
        
        // Time to update
        UpdateStatus();
        NotifyUI();
    }
}

void StatusBarGitMonitor::UpdateStatus() {
    m_updatePending = true;
    
    GitStatus newStatus;
    newStatus.isValid = false;
    
    // Check if we're in a git repo
    if (Utils::GitHelper::IsGitRepository()) {
        newStatus.branch = Utils::GitHelper::GetCurrentBranch();
        newStatus.commitHash = Utils::GitHelper::GetShortCommitHash();
        newStatus.isDirty = Utils::GitHelper::IsWorkingTreeDirty();
        newStatus.remoteStatus = Utils::GitHelper::GetRemoteStatus();
        newStatus.isValid = true;
    }
    
    // Update stored status (thread-safe)
    EnterCriticalSection(&m_statusCs);
    m_currentStatus = newStatus;
    LeaveCriticalSection(&m_statusCs);
    
    m_updatePending = false;
}

void StatusBarGitMonitor::NotifyUI() {
    if (!IsWindow(m_hwndNotify)) return;
    
    // Post message to UI thread
    // Note: In production, you'd allocate a GitStatus on heap and pass pointer
    // For simplicity, we just notify that update is ready
    PostMessage(m_hwndNotify, m_msgNotify, 0, 0);
}

//=============================================================================
// Global Integration Helpers
//=============================================================================

static StatusBarGitMonitor* g_gitMonitor = nullptr;

bool InitializeGitStatusBar(HWND hwndMain) {
    if (g_gitMonitor) return true;
    
    g_gitMonitor = new StatusBarGitMonitor();
    if (!g_gitMonitor->Initialize(hwndMain, WM_USER_GIT_STATUS_UPDATE)) {
        delete g_gitMonitor;
        g_gitMonitor = nullptr;
        return false;
    }
    
    // Start with 30 second interval
    return g_gitMonitor->StartMonitoring(30000);
}

void ShutdownGitStatusBar() {
    if (g_gitMonitor) {
        delete g_gitMonitor;
        g_gitMonitor = nullptr;
    }
}

void HandleGitStatusUpdate(HWND hwnd, WPARAM wParam, LPARAM lParam) {
    if (!g_gitMonitor) return;
    
    auto status = g_gitMonitor->GetCurrentStatus();
    std::string displayText = FormatGitStatusForDisplay(status);
    
    // Update status bar text (implementation depends on your StatusBar class)
    // Example: SendMessage(hwndStatusBar, SB_SETTEXT, 1, (LPARAM)displayText.c_str());
    
    // For now, just log it
    OutputDebugStringA("Git Status: ");
    OutputDebugStringA(displayText.c_str());
    OutputDebugStringA("\n");
}

std::string FormatGitStatusForDisplay(const StatusBarGitMonitor::GitStatus& status) {
    if (!status.isValid) {
        return "";
    }
    
    std::string result = status.branch;
    
    // Add commit hash if available
    if (!status.commitHash.empty()) {
        result += " @ " + status.commitHash.substr(0, 7);
    }
    
    // Add dirty indicator
    if (status.isDirty) {
        result += " *";
    }
    
    // Add remote status
    if (!status.remoteStatus.empty()) {
        result += " [" + status.remoteStatus + "]";
    }
    
    return result;
}

} // namespace Win32
} // namespace RawrXD
