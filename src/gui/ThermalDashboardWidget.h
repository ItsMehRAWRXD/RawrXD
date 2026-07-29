<<<<<<< HEAD
#pragma once
// ============================================================================
// ThermalDashboardWidget.h — Pure Win32 Native Implementation
// ============================================================================
// Live NVMe thermal visualization with tier detection, TurboSparse stats,
// and PowerInfer GPU/CPU split display. Loads pocket_lab_turbo.dll at runtime.
// ============================================================================

#include <windows.h>
#include <string>
#include <cstdint>

#pragma pack(push, 1)
struct ThermalSnapshot {
    double t0, t1, t2, t3, t4;
    unsigned int tier;
    unsigned int sparseSkipPct;
    unsigned int gpuSplit;
};
#pragma pack(pop)

typedef int  (__stdcall *PFN_THERMAL_INIT)();
typedef int  (__stdcall *PFN_THERMAL_GET)(ThermalSnapshot*);
typedef void (__stdcall *PFN_THERMAL_SHUTDOWN)();

class ThermalDashboardWidget {
public:
    explicit ThermalDashboardWidget(HWND parentWnd);
    ~ThermalDashboardWidget();

    bool isConnected() const { return m_dllLoaded; }
    void refresh();

    HWND getHwnd() const { return m_hwnd; }
    void show();
    void hide();
    void resize(int x, int y, int w, int h);

private:
    void createWindow(HWND parent);
    void loadDll();
    void paint(HDC hdc, const RECT& rc);
    void paintTempBar(HDC hdc, int x, int y, int w, int h, double tempC, int idx);
    void paintInfoPanel(HDC hdc, int x, int y, int w, int h);
    std::wstring tierName(unsigned int tier) const;
    COLORREF tempColor(double tempC) const;

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    HWND m_hwnd = nullptr;
    HWND m_parentWnd = nullptr;

    // DLL state
    bool m_dllLoaded = false;
    HMODULE m_hDll = nullptr;
    PFN_THERMAL_INIT m_pfnInit = nullptr;
    PFN_THERMAL_GET m_pfnGetThermal = nullptr;
    PFN_THERMAL_SHUTDOWN m_pfnShutdown = nullptr;

    // Snapshot data
    double m_temps[5] = { 35.0, 35.0, 35.0, 35.0, 35.0 };
    unsigned int m_tier = 0;
    unsigned int m_sparseSkipPct = 0;
    unsigned int m_gpuSplit = 100;

    // GDI resources
    HBITMAP m_backBuffer = nullptr;
    HDC m_backDC = nullptr;
    int m_bufW = 0, m_bufH = 0;
    HFONT m_fontTitle = nullptr;
    HFONT m_fontBody = nullptr;
    HFONT m_fontSmall = nullptr;
    HFONT m_fontLarge = nullptr;

    UINT_PTR m_timerId = 0;
};
=======
/**
 * @file ThermalDashboardWidget.h
 * @brief Win32/Direct2D widget displaying live NVMe thermal data + inference stats
 *
 * Connects to Pocket-Lab Turbo DLL for:
 * - Real-time NVMe temperatures (5 drives)
 * - Auto-detected tier (70B/120B/800B)
 * - TurboSparse skip percentage
 * - PowerInfer GPU/CPU split
 */
#pragma once

#include "../RawrXD_Foundation.h"
#include <d2d1.h>
#include <dwrite.h>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")

class ThermalDashboardWidget {
public:
    ThermalDashboardWidget();
    ~ThermalDashboardWidget();

    /// Create the Win32 window
    bool Create(HWND parent, int x, int y, int width, int height);

    /// Check if DLL is loaded and functional
    bool isConnected() const { return m_dllLoaded; }

    HWND GetHwnd() const { return m_hwnd; }

    void SetSize(int width, int height);

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    HRESULT CreateDeviceResources();
    void DiscardDeviceResources();
    void OnPaint();
    void OnResize(UINT width, UINT height);
    void OnTimer();

    void loadDll();
    
    // Window Handle
    HWND m_hwnd;

    // Direct2D Resources
    ID2D1Factory* m_pD2DFactory;
    ID2D1HwndRenderTarget* m_pRenderTarget;
    IDWriteFactory* m_pDWriteFactory;
    IDWriteTextFormat* m_pTextFormat;

    // Brushes
    ID2D1SolidColorBrush* m_pBrushCool;
    ID2D1SolidColorBrush* m_pBrushWarm;
    ID2D1SolidColorBrush* m_pBrushHot;
    ID2D1SolidColorBrush* m_pBrushBg;
    ID2D1SolidColorBrush* m_pBrushText;
    ID2D1SolidColorBrush* m_pBrushAccent;

    // DLL state
    bool m_dllLoaded;
    void* m_hDll;

    // Function pointers
    typedef int (__stdcall *PFN_Init)(void);
    typedef void (__stdcall *PFN_GetThermal)(void*);

    PFN_Init m_pfnInit;
    PFN_GetThermal m_pfnGetThermal;

    // Cached thermal data
    double m_temps[5];
    unsigned int m_tier;
    unsigned int m_sparseSkipPct;
    unsigned int m_gpuSplit;

    // Thresholds
    static constexpr int TEMP_WARN = 45;
    static constexpr int TEMP_CRIT = 55;
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
