#include "ide/ArchitectureDiagram.hpp"
#include <sstream>
#include <iomanip>

namespace Sovereign {
namespace IDE {

bool ArchitectureDiagram::Create(HWND parent) {
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SovereignArchitectureDiagram";
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    
    if (!RegisterClassExW(&wc)) {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }
    }
    
    m_hwnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SovereignArchitectureDiagram",
        L"Architecture Diagram",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_CLIPCHILDREN,
        0, 0, 400, 600,
        parent, nullptr, GetModuleHandle(nullptr), this
    );
    
    if (!m_hwnd) return false;
    
    m_hFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Consolas");
    
    return true;
}

void ArchitectureDiagram::Destroy() {
    if (m_hFont) {
        DeleteObject(m_hFont);
        m_hFont = nullptr;
    }
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void ArchitectureDiagram::Load(const std::vector<LayerInfo>& layers) {
    m_layers = layers;
    
    // Set scroll range
    int totalHeight = MARGIN_TOP + (m_layers.size() * LAYER_SPACING) + 50;
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE;
    si.nMin = 0;
    si.nMax = totalHeight;
    si.nPage = 100;
    SetScrollInfo(m_hwnd, SB_VERT, &si, TRUE);
    
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void ArchitectureDiagram::Clear() {
    m_layers.clear();
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void ArchitectureDiagram::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    
    // Background
    FillRect(hdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
    
    SelectObject(hdc, m_hFont);
    SetBkMode(hdc, TRANSPARENT);
    
    // Get scroll position
    int scrollY = GetScrollPos(m_hwnd, SB_VERT);
    
    int y = MARGIN_TOP - scrollY;
    int width = rc.right - MARGIN_LEFT - MARGIN_RIGHT;
    
    // Title
    SetTextColor(hdc, RGB(0, 0, 0));
    TextOutW(hdc, MARGIN_LEFT, y, L"🏗️ Model Architecture", 20);
    y += 30;
    
    // Draw each layer
    for (const auto& layer : m_layers) {
        DrawLayer(hdc, layer, MARGIN_LEFT, y, width);
        y += LAYER_SPACING;
    }
    
    // Legend
    y += 20;
    SetTextColor(hdc, RGB(100, 100, 100));
    TextOutW(hdc, MARGIN_LEFT, y, L"Legend: FFN size = thickness, Experts = color intensity", 55);
}

void ArchitectureDiagram::DrawLayer(HDC hdc, const LayerInfo& layer, int x, int y, int width) {
    // Calculate bar height based on FFN size (min 20, max 60)
    int barHeight = 20 + (layer.ffnSize / 1024);
    if (barHeight > 60) barHeight = 60;
    
    // Draw layer block
    HBRUSH brush = CreateSolidBrush(GetLayerColor(layer));
    RECT layerRect = { x, y, x + width, y + barHeight };
    FillRect(hdc, &layerRect, brush);
    DeleteObject(brush);
    
    // Draw border
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(50, 50, 50));
    SelectObject(hdc, pen);
    Rectangle(hdc, x, y, x + width, y + barHeight);
    DeleteObject(pen);
    
    // Draw attention heads
    DrawAttentionHeads(hdc, layer, x, y, width, barHeight);
    
    // Draw layer label
    SetTextColor(hdc, RGB(0, 0, 0));
    wchar_t label[256];
    swprintf_s(label, L"L%u: H=%u FFN=%u Heads=%u Experts=%u KV=[%u..%u]%s",
        layer.layerIndex,
        layer.hiddenSize,
        layer.ffnSize,
        layer.attentionHeads,
        layer.numExperts,
        layer.kvSegmentStart,
        layer.kvSegmentStart + layer.kvSegmentCount - 1,
        layer.quantized ? L" [Q]" : L"");
    TextOutW(hdc, x + 5, y + barHeight + 2, label, wcslen(label));
}

void ArchitectureDiagram::DrawAttentionHeads(HDC hdc, const LayerInfo& layer, int x, int y, int width, int height) {
    if (layer.attentionHeads == 0) return;
    
    int headWidth = width / layer.attentionHeads;
    if (headWidth < 2) headWidth = 2;
    
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(100, 100, 100));
    SelectObject(hdc, pen);
    
    for (uint32_t h = 0; h < layer.attentionHeads && h < 32; h++) {
        int headX = x + (h * headWidth);
        MoveToEx(hdc, headX, y, nullptr);
        LineTo(hdc, headX, y + height);
    }
    
    DeleteObject(pen);
}

COLORREF ArchitectureDiagram::GetLayerColor(const LayerInfo& layer) {
    // Color intensity based on expert count
    int intensity = 255 - (layer.numExperts * 10);
    if (intensity < 100) intensity = 100;
    
    if (layer.quantized) {
        // Quantized layers get a blue tint
        return RGB(intensity - 50, intensity, 255);
    } else {
        // Normal layers get a purple tint
        return RGB(intensity, intensity - 50, 255);
    }
}

COLORREF ArchitectureDiagram::GetQuantizationColor(bool quantized) {
    return quantized ? RGB(100, 100, 255) : RGB(200, 200, 255);
}

void ArchitectureDiagram::OnPaint() {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(m_hwnd, &ps);
    Render(hdc);
    EndPaint(m_hwnd, &ps);
}

LRESULT CALLBACK ArchitectureDiagram::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    ArchitectureDiagram* diagram = nullptr;
    
    if (msg == WM_CREATE) {
        auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        diagram = reinterpret_cast<ArchitectureDiagram*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(diagram));
    } else {
        diagram = reinterpret_cast<ArchitectureDiagram*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    switch (msg) {
        case WM_PAINT:
            if (diagram) diagram->OnPaint();
            return 0;
            
        case WM_VSCROLL: {
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_VERT, &si);
            
            int pos = si.nPos;
            switch (LOWORD(wParam)) {
                case SB_LINEUP: pos -= 10; break;
                case SB_LINEDOWN: pos += 10; break;
                case SB_PAGEUP: pos -= si.nPage; break;
                case SB_PAGEDOWN: pos += si.nPage; break;
                case SB_THUMBTRACK: pos = HIWORD(wParam); break;
            }
            
            si.fMask = SIF_POS;
            si.nPos = pos;
            SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        }
        
        case WM_DESTROY:
            return 0;
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

} // namespace IDE
} // namespace Sovereign
