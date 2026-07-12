#include "ide/MoETimeline.hpp"
#include <cstring>

namespace Sovereign {
namespace IDE {

bool MoETimeline::Create(HWND parent) {
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SovereignMoETimeline";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    
    if (!RegisterClassExW(&wc)) {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }
    }
    
    m_hwnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SovereignMoETimeline",
        L"MoE Routing Timeline",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        0, 0, 600, 250,
        parent, nullptr, GetModuleHandle(nullptr), this
    );
    
    return m_hwnd != nullptr;
}

void MoETimeline::Destroy() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void MoETimeline::OnBeacon(const Beacon& beacon) {
    // Check if this is a MoE health beacon
    if (beacon.id == 0xB03 || beacon.id == 0x403 || beacon.id == 0x404) {
        uint8_t expert = beacon.payload & 0x3F;
        uint8_t activation = (beacon.payload >> 6) & 0x3;
        
        m_events.push_back({expert, activation, beacon.timestamp});
        
        // Keep only last N events
        if (m_events.size() > MAX_EVENTS) {
            m_events.erase(m_events.begin());
        }
        
        InvalidateRect(m_hwnd, nullptr, FALSE);
    }
}

void MoETimeline::Update() {
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void MoETimeline::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    
    // Background
    FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
    
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    
    // Draw grid
    DrawGrid(hdc, width, height);
    
    // Draw events
    DrawEvents(hdc, width, height);
    
    // Draw legend
    DrawLegend(hdc, 10, height - 25);
}

void MoETimeline::DrawGrid(HDC hdc, int width, int height) {
    HPEN pen = CreatePen(PS_DOT, 1, RGB(40, 40, 40));
    SelectObject(hdc, pen);
    
    // Horizontal lines for experts
    int yStep = (height - 50) / EXPERT_COUNT;
    for (int i = 0; i <= EXPERT_COUNT; i += 8) {
        int y = 10 + (i * yStep);
        MoveToEx(hdc, 50, y, nullptr);
        LineTo(hdc, width, y);
    }
    
    // Vertical lines for time
    for (int x = 50; x < width; x += 50) {
        MoveToEx(hdc, x, 10, nullptr);
        LineTo(hdc, x, height - 40);
    }
    
    DeleteObject(pen);
    
    // Expert labels
    SetTextColor(hdc, RGB(150, 150, 150));
    SetBkMode(hdc, TRANSPARENT);
    for (int i = 0; i < EXPERT_COUNT; i += 8) {
        int y = 10 + (i * ((height - 50) / EXPERT_COUNT));
        wchar_t buf[8];
        swprintf_s(buf, L"E%d", i);
        TextOutW(hdc, 5, y - 6, buf, wcslen(buf));
    }
}

void MoETimeline::DrawEvents(HDC hdc, int width, int height) {
    if (m_events.empty()) return;
    
    int xStep = (width - 50) / MAX_EVENTS;
    if (xStep < 1) xStep = 1;
    
    int yStep = (height - 50) / EXPERT_COUNT;
    if (yStep < 1) yStep = 1;
    
    int startIdx = (m_events.size() > MAX_EVENTS) ? m_events.size() - MAX_EVENTS : 0;
    
    for (size_t i = startIdx; i < m_events.size(); i++) {
        const auto& evt = m_events[i];
        int x = 50 + ((i - startIdx) * xStep);
        int y = 10 + (evt.expertIndex * yStep);
        
        COLORREF color = GetActivationColor(evt.activationLevel);
        
        // Draw activation cell
        int cellHeight = yStep - 1;
        if (cellHeight < 2) cellHeight = 2;
        
        HBRUSH brush = CreateSolidBrush(color);
        RECT r = { x, y, x + xStep + 1, y + cellHeight };
        FillRect(hdc, &r, brush);
        DeleteObject(brush);
    }
}

void MoETimeline::DrawLegend(HDC hdc, int x, int y) {
    SetTextColor(hdc, RGB(150, 150, 150));
    SetBkMode(hdc, TRANSPARENT);
    
    TextOutW(hdc, x, y, L"Activation: Low", 15);
    
    // Draw activation gradient
    for (int i = 0; i < 4; i++) {
        COLORREF color = GetActivationColor(i);
        HBRUSH brush = CreateSolidBrush(color);
        RECT r = { x + 110 + (i * 25), y, x + 130 + (i * 25), y + 15 };
        FillRect(hdc, &r, brush);
        DeleteObject(brush);
    }
    
    TextOutW(hdc, x + 215, y, L"High", 4);
}

COLORREF MoETimeline::GetActivationColor(uint8_t level) {
    switch (level) {
        case 0: return RGB(50, 100, 50);      // Low - dark green
        case 1: return RGB(100, 200, 100);    // Medium - green
        case 2: return RGB(200, 255, 100);    // High - yellow-green
        case 3: return RGB(255, 255, 50);     // Very high - yellow
        default: return RGB(100, 100, 100);
    }
}

void MoETimeline::OnPaint() {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(m_hwnd, &ps);
    Render(hdc);
    EndPaint(m_hwnd, &ps);
}

LRESULT CALLBACK MoETimeline::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    MoETimeline* timeline = nullptr;
    
    if (msg == WM_CREATE) {
        auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        timeline = reinterpret_cast<MoETimeline*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(timeline));
    } else {
        timeline = reinterpret_cast<MoETimeline*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    switch (msg) {
        case WM_PAINT:
            if (timeline) timeline->OnPaint();
            return 0;
            
        case WM_TIMER:
            if (timeline) timeline->Update();
            return 0;
            
        case WM_DESTROY:
            return 0;
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

} // namespace IDE
} // namespace Sovereign
