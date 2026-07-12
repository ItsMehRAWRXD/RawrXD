#include "ide/KVHeatmap.hpp"
#include <cstring>

namespace Sovereign {
namespace IDE {

bool KVHeatmap::Create(HWND parent) {
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SovereignKVHeatmap";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    
    if (!RegisterClassExW(&wc)) {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }
    }
    
    m_hwnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SovereignKVHeatmap",
        L"KV Heatmap Timeline",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        0, 0, 600, 150,
        parent, nullptr, GetModuleHandle(nullptr), this
    );
    
    return m_hwnd != nullptr;
}

void KVHeatmap::Destroy() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void KVHeatmap::OnBeacon(const Beacon& beacon) {
    // Check if this is a KV health beacon
    if (beacon.id >= 0xB00 && beacon.id <= 0xB09) {
        int tier = beacon.payload & 0x3;           // 0=hot, 1=warm, 2=cold
        int pressure = (beacon.payload >> 2) & 0xFF;
        
        m_timeline.push_back({tier, pressure, beacon.timestamp});
        
        // Keep only last N points
        if (m_timeline.size() > MAX_POINTS) {
            m_timeline.erase(m_timeline.begin());
        }
        
        InvalidateRect(m_hwnd, nullptr, FALSE);
    }
}

void KVHeatmap::Update() {
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void KVHeatmap::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    
    // Background
    FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
    
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    
    // Draw timeline
    DrawTimeline(hdc, width, height);
    
    // Draw legend
    DrawLegend(hdc, 10, height - 35);
}

void KVHeatmap::DrawTimeline(HDC hdc, int width, int height) {
    if (m_timeline.empty()) return;
    
    int xStep = width / MAX_POINTS;
    if (xStep < 1) xStep = 1;
    
    // Draw tier labels
    SetTextColor(hdc, RGB(200, 200, 200));
    SetBkMode(hdc, TRANSPARENT);
    
    const wchar_t* tierLabels[] = { L"Hot", L"Warm", L"Cold" };
    for (int tier = 0; tier < 3; tier++) {
        int y = 10 + (tier * TIER_HEIGHT);
        TextOutW(hdc, 5, y, tierLabels[tier], wcslen(tierLabels[tier]));
        
        // Draw tier baseline
        HPEN pen = CreatePen(PS_DOT, 1, RGB(50, 50, 50));
        SelectObject(hdc, pen);
        MoveToEx(hdc, 50, y + 15, nullptr);
        LineTo(hdc, width, y + 15);
        DeleteObject(pen);
    }
    
    // Draw data points
    int startIdx = (m_timeline.size() > MAX_POINTS) ? m_timeline.size() - MAX_POINTS : 0;
    
    for (size_t i = startIdx; i < m_timeline.size(); i++) {
        const auto& point = m_timeline[i];
        int x = 50 + ((i - startIdx) * xStep);
        int y = 10 + (point.tier * TIER_HEIGHT) + 15;
        
        COLORREF color = GetTierColor(point.tier, point.pressure);
        
        // Draw pressure indicator
        int radius = 3 + (point.pressure / 32);
        HBRUSH brush = CreateSolidBrush(color);
        SelectObject(hdc, brush);
        Ellipse(hdc, x - radius, y - radius, x + radius, y + radius);
        DeleteObject(brush);
    }
}

void KVHeatmap::DrawLegend(HDC hdc, int x, int y) {
    SetTextColor(hdc, RGB(150, 150, 150));
    SetBkMode(hdc, TRANSPARENT);
    
    TextOutW(hdc, x, y, L"Pressure: Low", 13);
    
    // Draw pressure gradient
    for (int i = 0; i < 5; i++) {
        COLORREF color = RGB(50 + i * 40, 200 - i * 30, 50);
        HBRUSH brush = CreateSolidBrush(color);
        RECT r = { x + 100 + (i * 20), y, x + 115 + (i * 20), y + 15 };
        FillRect(hdc, &r, brush);
        DeleteObject(brush);
    }
    
    TextOutW(hdc, x + 210, y, L"High", 4);
}

COLORREF KVHeatmap::GetTierColor(int tier, int pressure) {
    // Normalize pressure to 0-255
    int p = pressure;
    if (p < 0) p = 0;
    if (p > 255) p = 255;
    
    switch (tier) {
        case 0: // Hot - red to yellow
            return RGB(255, 50 + p, 50);
        case 1: // Warm - yellow to orange
            return RGB(255, 150 + (p / 4), 50);
        case 2: // Cold - blue to cyan
            return RGB(50, 100 + (p / 3), 255);
        default:
            return RGB(200, 200, 200);
    }
}

void KVHeatmap::OnPaint() {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(m_hwnd, &ps);
    Render(hdc);
    EndPaint(m_hwnd, &ps);
}

LRESULT CALLBACK KVHeatmap::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    KVHeatmap* heatmap = nullptr;
    
    if (msg == WM_CREATE) {
        auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        heatmap = reinterpret_cast<KVHeatmap*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(heatmap));
    } else {
        heatmap = reinterpret_cast<KVHeatmap*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    switch (msg) {
        case WM_PAINT:
            if (heatmap) heatmap->OnPaint();
            return 0;
            
        case WM_TIMER:
            if (heatmap) heatmap->Update();
            return 0;
            
        case WM_DESTROY:
            return 0;
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

} // namespace IDE
} // namespace Sovereign
