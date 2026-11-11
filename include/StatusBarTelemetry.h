// StatusBarTelemetry.h
// RawrXD Win32IDE Status Bar Telemetry Display
// Real-time TPS, VRAM, temperature metrics

#pragma once
#include "omega1_ipc_protocol.h"
#include <windows.h>
#include <commctrl.h>
#include <string>

// Resource ID for status bar
#define IDC_STATUS_BAR  1001

// ─── Status Bar Telemetry Class ───
class StatusBarTelemetry {
public:
    StatusBarTelemetry() noexcept;
    ~StatusBarTelemetry();

    // No copy
    StatusBarTelemetry(const StatusBarTelemetry&) = delete;
    StatusBarTelemetry& operator=(const StatusBarTelemetry&) = delete;

    // ─── Initialization ───
    bool Initialize(HWND hwndParent, int numParts = 4);
    void Shutdown() noexcept;
    bool IsInitialized() const noexcept { return m_hwndStatus != nullptr; }

    // ─── Part Management ───
    void UpdatePartWidths();
    void SetPartText(int part, const wchar_t* text);

    // ─── Telemetry Updates ───
    void UpdateFromTelemetry(const O1StatusTelemetry& telemetry,
                              const std::string& modelName);
    void SetDisconnected();
    void SetConnecting();

    // ─── Window Message Handling ───
    void OnParentResize();
    bool HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);

    // ─── Accessors ───
    void SetUpdateInterval(int ms);
    HWND GetHandle() const noexcept;

private:
    static constexpr int MAX_PARTS = 4;

    HWND m_hwndStatus;
    HWND m_hwndParent;
    int m_partCount;
    int m_parts[MAX_PARTS];
    int m_updateIntervalMs;
    DWORD m_lastUpdateTick;
};
