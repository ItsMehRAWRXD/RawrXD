#include <windows.h>
#include <vector>
#include <string>
#include <atomic>
#include "sovereign/Beaconism.hpp"

using namespace Sovereign;

enum class HealthState {
    UNKNOWN,
    OK,
    WARNING,
    FAIL
};

struct HealthIndicator {
    std::string name;
    HealthState state;
    uint64_t lastUpdate;
    uint64_t lastSuccess;
    uint32_t beaconCount;
};

class SovereignHealthPanel {
    HWND m_hwnd = nullptr;
    HFONT m_hFont = nullptr;
    std::vector<HealthIndicator> m_indicators;
    std::atomic<bool> m_running{false};
    HANDLE m_hThread = nullptr;
    
    static constexpr uint32_t REFRESH_MS = 1000;
    static constexpr uint64_t STALE_THRESHOLD_MS = 30000;
    
public:
    bool Create(HWND parent);
    void Destroy();
    void UpdateFromBeacons();
    void OnBeacon(const Beacon& beacon);
    void Render(HDC hdc);
    HWND GetHWND() const { return m_hwnd; }
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static DWORD WINAPI RefreshThread(LPVOID param);
};

bool SovereignHealthPanel::Create(HWND parent) {
    // Register window class
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SovereignHealthPanel";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    
    if (!RegisterClassExW(&wc)) {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }
    }
    
    // Create window
    m_hwnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SovereignHealthPanel",
        L"Sovereign Health",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        0, 0, 350, 400,
        parent, nullptr, GetModuleHandle(nullptr), this
    );
    
    if (!m_hwnd) return false;
    
    // Create font
    m_hFont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Consolas");
    
    // Initialize indicators
    m_indicators = {
        {"KV Cache", HealthState::UNKNOWN, 0, 0, 0},
        {"Expert Cache", HealthState::UNKNOWN, 0, 0, 0},
        {"Attention", HealthState::UNKNOWN, 0, 0, 0},
        {"MoE Router", HealthState::UNKNOWN, 0, 0, 0},
        {"NVMe I/O", HealthState::UNKNOWN, 0, 0, 0},
        {"Vulkan Compute", HealthState::UNKNOWN, 0, 0, 0},
        {"Model Loader", HealthState::UNKNOWN, 0, 0, 0},
        {"Replay System", HealthState::UNKNOWN, 0, 0, 0},
        {"Telemetry", HealthState::UNKNOWN, 0, 0, 0},
        {"Beaconism", HealthState::UNKNOWN, 0, 0, 0}
    };
    
    // Start refresh thread
    m_running = true;
    m_hThread = CreateThread(nullptr, 0, RefreshThread, this, 0, nullptr);
    
    return true;
}

void SovereignHealthPanel::Destroy() {
    m_running = false;
    if (m_hThread) {
        WaitForSingleObject(m_hThread, 2000);
        CloseHandle(m_hThread);
        m_hThread = nullptr;
    }
    if (m_hFont) {
        DeleteObject(m_hFont);
        m_hFont = nullptr;
    }
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void SovereignHealthPanel::UpdateFromBeacons() {
    // Check staleness
    auto now = GetTickCount64();
    for (auto& ind : m_indicators) {
        if (ind.state == HealthState::OK) {
            auto age = now - ind.lastSuccess;
            if (age > STALE_THRESHOLD_MS) {
                ind.state = HealthState::WARNING;
            }
        }
    }
}

void SovereignHealthPanel::OnBeacon(const Beacon& beacon) {
    int idx = -1;
    HealthState newState = HealthState::UNKNOWN;
    
    switch (static_cast<BeaconID>(beacon.id)) {
        case BeaconID::KV_DONE: idx = 0; newState = HealthState::OK; break;
        case BeaconID::EXPERT_DONE: idx = 1; newState = HealthState::OK; break;
        case BeaconID::ATTENTION_DONE: idx = 2; newState = HealthState::OK; break;
        case BeaconID::MOE_DONE: idx = 3; newState = HealthState::OK; break;
        case BeaconID::NVME_DONE: idx = 4; newState = HealthState::OK; break;
        case BeaconID::VULKAN_DONE: idx = 5; newState = HealthState::OK; break;
        case BeaconID::MODEL_DONE: idx = 6; newState = HealthState::OK; break;
        case BeaconID::REPLAY_DONE: idx = 7; newState = HealthState::OK; break;
        case BeaconID::TELEMETRY_DONE: idx = 8; newState = HealthState::OK; break;
        case BeaconID::BEACONISM_TEST: idx = 9; newState = HealthState::OK; break;
        default: break;
    }
    
    if (idx >= 0 && idx < m_indicators.size()) {
        auto now = GetTickCount64();
        m_indicators[idx].state = newState;
        m_indicators[idx].lastUpdate = now;
        m_indicators[idx].lastSuccess = now;
        m_indicators[idx].beaconCount++;
    }
}

void SovereignHealthPanel::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    
    // Background
    FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
    
    SelectObject(hdc, m_hFont);
    SetBkMode(hdc, TRANSPARENT);
    
    int y = 10;
    int lineHeight = 24;
    
    // Title
    SetTextColor(hdc, RGB(255, 255, 255));
    TextOutW(hdc, 10, y, L"🛡️ SOVEREIGN HEALTH", 19);
    y += lineHeight + 5;
    
    // Separator
    HPEN hPen = CreatePen(PS_SOLID, 1, RGB(64, 64, 64));
    SelectObject(hdc, hPen);
    MoveToEx(hdc, 10, y, nullptr);
    LineTo(hdc, rc.right - 10, y);
    DeleteObject(hPen);
    y += 10;
    
    // Indicators
    for (auto& ind : m_indicators) {
        // Determine color and symbol
        COLORREF color;
        const wchar_t* symbol;
        
        switch (ind.state) {
            case HealthState::OK:
                color = RGB(0, 255, 0);
                symbol = L"🟢";
                break;
            case HealthState::WARNING:
                color = RGB(255, 165, 0);
                symbol = L"🟡";
                break;
            case HealthState::FAIL:
                color = RGB(255, 0, 0);
                symbol = L"🔴";
                break;
            default:
                color = RGB(128, 128, 128);
                symbol = L"⚪";
        }
        
        SetTextColor(hdc, color);
        
        wchar_t buf[256];
        int len = MultiByteToWideChar(CP_UTF8, 0, ind.name.c_str(), -1, buf, 256);
        
        wchar_t display[512];
        swprintf_s(display, L"%s %s", symbol, buf);
        TextOutW(hdc, 10, y, display, wcslen(display));
        
        // Show beacon count
        if (ind.beaconCount > 0) {
            SetTextColor(hdc, RGB(128, 128, 128));
            wchar_t count[32];
            swprintf_s(count, L"(%u)", ind.beaconCount);
            TextOutW(hdc, 200, y, count, wcslen(count));
        }
        
        y += lineHeight;
    }
    
    // Overall status
    y += 10;
    int ok = 0, warn = 0, fail = 0;
    for (auto& ind : m_indicators) {
        switch (ind.state) {
            case HealthState::OK: ok++; break;
            case HealthState::WARNING: warn++; break;
            case HealthState::FAIL: fail++; break;
            default: break;
        }
    }
    
    COLORREF statusColor;
    if (fail > 0) statusColor = RGB(255, 0, 0);
    else if (warn > 0) statusColor = RGB(255, 165, 0);
    else statusColor = RGB(0, 255, 0);
    
    SetTextColor(hdc, statusColor);
    wchar_t status[256];
    swprintf_s(status, L"Status: %d/%d healthy", ok, (int)m_indicators.size());
    if (warn > 0) swprintf_s(status + wcslen(status), 256 - wcslen(status), L", %d warn", warn);
    if (fail > 0) swprintf_s(status + wcslen(status), 256 - wcslen(status), L", %d fail", fail);
    TextOutW(hdc, 10, y, status, wcslen(status));
}

LRESULT CALLBACK SovereignHealthPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    SovereignHealthPanel* panel = nullptr;
    
    if (msg == WM_CREATE) {
        auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        panel = reinterpret_cast<SovereignHealthPanel*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(panel));
    } else {
        panel = reinterpret_cast<SovereignHealthPanel*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            if (panel) panel->Render(hdc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_TIMER:
            if (panel) {
                panel->UpdateFromBeacons();
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            return 0;
        case WM_DESTROY:
            return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

DWORD WINAPI SovereignHealthPanel::RefreshThread(LPVOID param) {
    auto* panel = static_cast<SovereignHealthPanel*>(param);
    
    while (panel->m_running) {
        panel->UpdateFromBeacons();
        InvalidateRect(panel->m_hwnd, nullptr, FALSE);
        Sleep(REFRESH_MS);
    }
    
    return 0;
}

// C API for IDE integration
extern "C" {
    __declspec(dllexport) void* SovereignHealthPanel_Create(HWND parent) {
        auto* panel = new SovereignHealthPanel();
        if (!panel->Create(parent)) {
            delete panel;
            return nullptr;
        }
        return panel;
    }
    
    __declspec(dllexport) void SovereignHealthPanel_Destroy(void* handle) {
        auto* panel = static_cast<SovereignHealthPanel*>(handle);
        if (panel) {
            panel->Destroy();
            delete panel;
        }
    }
    
    __declspec(dllexport) HWND SovereignHealthPanel_GetHwnd(void* handle) {
        auto* panel = static_cast<SovereignHealthPanel*>(handle);
        return panel ? panel->m_hwnd : nullptr;
    }
}
