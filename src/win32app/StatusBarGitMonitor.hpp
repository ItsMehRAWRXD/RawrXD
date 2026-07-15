//=============================================================================
// RawrXD Status Bar Git Integration
// Thread-safe, timer-based git status updates for Win32IDE
//=============================================================================
#pragma once

#include "../utils/GitHelper.hpp"
#include <windows.h>
#include <string>
#include <atomic>

namespace RawrXD {
namespace Win32 {

//=============================================================================
// Status Bar Git Monitor
// Updates git status periodically without blocking UI thread
//=============================================================================

class StatusBarGitMonitor {
public:
    StatusBarGitMonitor();
    ~StatusBarGitMonitor();
    
    // Initialize with window handle for PostMessage notifications
    bool Initialize(HWND hwndNotify, UINT msgNotify);
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Start monitoring (creates background thread)
    bool StartMonitoring(DWORD intervalMs = 30000);  // Default: 30 seconds
    
    // Stop monitoring
    void StopMonitoring();
    
    // Force immediate update (non-blocking)
    void RequestImmediateUpdate();
    
    // Get current status (thread-safe)
    struct GitStatus {
        std::string branch;
        std::string commitHash;
        bool isDirty = false;
        std::string remoteStatus;
        bool isValid = false;
    };
    GitStatus GetCurrentStatus() const;
    
    // Check if update is pending
    bool IsUpdatePending() const;

private:
    // Background thread function
    static DWORD WINAPI MonitorThreadProc(LPVOID param);
    void MonitorLoop();
    
    // Perform git status update
    void UpdateStatus();
    
    // Notify UI thread
    void NotifyUI();
    
    // Thread handles
    HANDLE m_hMonitorThread = NULL;
    HANDLE m_hStopEvent = NULL;
    HANDLE m_hUpdateEvent = NULL;
    
    // Notification target
    HWND m_hwndNotify = NULL;
    UINT m_msgNotify = 0;
    
    // Update interval
    DWORD m_intervalMs = 30000;
    
    // Thread-safe status storage
    mutable CRITICAL_SECTION m_statusCs;
    GitStatus m_currentStatus;
    
    // Atomic flags
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_updatePending{false};
};

//=============================================================================
// Window Message Constants
//=============================================================================

// Message sent to main window when git status updates
// wParam: 0 (reserved)
// lParam: pointer to GitStatus (must be copied then freed by receiver)
#ifndef WM_USER_GIT_STATUS_UPDATE
#define WM_USER_GIT_STATUS_UPDATE (WM_USER + 0x700)
#endif

//=============================================================================
// Helper Functions for Win32IDE Integration
//=============================================================================

// Initialize git monitoring in Win32IDE
bool InitializeGitStatusBar(HWND hwndMain);

// Shutdown git monitoring
void ShutdownGitStatusBar();

// Handle WM_USER_GIT_STATUS_UPDATE in WndProc
void HandleGitStatusUpdate(HWND hwnd, WPARAM wParam, LPARAM lParam);

// Format git status for display
std::string FormatGitStatusForDisplay(const StatusBarGitMonitor::GitStatus& status);

} // namespace Win32
} // namespace RawrXD
