#include "ide/GPUPipelineGraph.hpp"
#include <sstream>
#include <iomanip>

namespace Sovereign {
namespace IDE {

bool GPUPipelineGraph::Create(HWND parent) {
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SovereignGPUPipelineGraph";
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    
    if (!RegisterClassExW(&wc)) {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            return false;
        }
    }
    
    m_hwnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SovereignGPUPipelineGraph",
        L"GPU Pipeline Graph",
        WS_CHILD | WS_VISIBLE | WS_HSCROLL | WS_CLIPCHILDREN,
        0, 0, 800, 300,
        parent, nullptr, GetModuleHandle(nullptr), this
    );
    
    if (!m_hwnd) return false;
    
    m_hFont = CreateFontW(11, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Consolas");
    
    return true;
}

void GPUPipelineGraph::Destroy() {
    if (m_hFont) {
        DeleteObject(m_hFont);
        m_hFont = nullptr;
    }
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

void GPUPipelineGraph::Update(const std::vector<GPUDispatch>& dispatches) {
    m_dispatches = dispatches;
    
    // Limit number of dispatches
    if (m_dispatches.size() > MAX_DISPATCHES) {
        m_dispatches.erase(m_dispatches.begin(), 
            m_dispatches.begin() + (m_dispatches.size() - MAX_DISPATCHES));
    }
    
    // Update scroll range
    int totalWidth = m_dispatches.size() * (NODE_WIDTH + 20);
    SCROLLINFO si = {};
    si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE;
    si.nMin = 0;
    si.nMax = totalWidth;
    si.nPage = 100;
    SetScrollInfo(m_hwnd, SB_HORZ, &si, TRUE);
    
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void GPUPipelineGraph::AddDispatch(const GPUDispatch& dispatch) {
    m_dispatches.push_back(dispatch);
    
    if (m_dispatches.size() > MAX_DISPATCHES) {
        m_dispatches.erase(m_dispatches.begin());
    }
    
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void GPUPipelineGraph::Clear() {
    m_dispatches.clear();
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void GPUPipelineGraph::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    
    // Background
    FillRect(hdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
    
    SelectObject(hdc, m_hFont);
    SetBkMode(hdc, TRANSPARENT);
    
    // Get scroll position
    int scrollX = GetScrollPos(m_hwnd, SB_HORZ);
    
    int x = 20 - scrollX;
    int y = rc.bottom / 2 - NODE_HEIGHT / 2;
    
    // Draw title
    SetTextColor(hdc, RGB(0, 0, 0));
    TextOutW(hdc, 20 - scrollX, 10, L"🎮 GPU Pipeline Execution", 24);
    
    // Draw nodes and edges
    for (size_t i = 0; i < m_dispatches.size(); i++) {
        const auto& dispatch = m_dispatches[i];
        
        // Draw edge to next node
        if (i < m_dispatches.size() - 1) {
            int nextX = x + NODE_WIDTH + 20;
            DrawEdge(hdc, x + NODE_WIDTH, y + NODE_HEIGHT / 2, 
                     nextX, y + NODE_HEIGHT / 2, dispatch.durationNs);
        }
        
        // Draw node
        DrawNode(hdc, dispatch, x, y);
        
        x += NODE_WIDTH + 20;
    }
    
    // Draw legend
    DrawLegend(hdc, 20 - scrollX, rc.bottom - 40);
}

void GPUPipelineGraph::DrawNode(HDC hdc, const GPUDispatch& dispatch, int x, int y) {
    // Node background
    COLORREF color = GetPipelineColor(dispatch.pipelineID);
    HBRUSH brush = CreateSolidBrush(color);
    RECT nodeRect = { x, y, x + NODE_WIDTH, y + NODE_HEIGHT };
    FillRect(hdc, &nodeRect, brush);
    DeleteObject(brush);
    
    // Node border
    HPEN pen = CreatePen(PS_SOLID, 2, RGB(50, 50, 50));
    SelectObject(hdc, pen);
    Rectangle(hdc, x, y, x + NODE_WIDTH, y + NODE_HEIGHT);
    DeleteObject(pen);
    
    // Node text
    SetTextColor(hdc, RGB(0, 0, 0));
    
    // Pipeline name
    std::wstring name(dispatch.pipelineName.begin(), dispatch.pipelineName.end());
    if (name.length() > 15) {
        name = name.substr(0, 12) + L"...";
    }
    TextOutW(hdc, x + 5, y + 3, name.c_str(), (int)name.length());
    
    // Workgroup size
    wchar_t wgBuf[64];
    swprintf_s(wgBuf, L"WG: %u,%u,%u", 
        dispatch.workgroupsX, dispatch.workgroupsY, dispatch.workgroupsZ);
    TextOutW(hdc, x + 5, y + 18, wgBuf, wcslen(wgBuf));
    
    // Duration
    std::wostringstream durStr;
    if (dispatch.durationNs < 1000) {
        durStr << dispatch.durationNs << L"ns";
    } else if (dispatch.durationNs < 1000000) {
        durStr << std::fixed << std::setprecision(1) << (dispatch.durationNs / 1000.0) << L"us";
    } else {
        durStr << std::fixed << std::setprecision(2) << (dispatch.durationNs / 1000000.0) << L"ms";
    }
    TextOutW(hdc, x + 5, y + 30, durStr.str().c_str(), (int)durStr.str().length());
}

void GPUPipelineGraph::DrawEdge(HDC hdc, int x1, int y1, int x2, int y2, uint64_t duration) {
    int thickness = GetLineThickness(duration);
    
    HPEN pen = CreatePen(PS_SOLID, thickness, RGB(100, 100, 100));
    SelectObject(hdc, pen);
    
    // Draw arrow
    MoveToEx(hdc, x1, y1, nullptr);
    LineTo(hdc, x2, y2);
    
    // Arrow head
    int arrowSize = 8;
    POINT arrow[] = {
        { x2 - arrowSize, y2 - arrowSize / 2 },
        { x2, y2 },
        { x2 - arrowSize, y2 + arrowSize / 2 }
    };
    Polyline(hdc, arrow, 3);
    
    DeleteObject(pen);
}

void GPUPipelineGraph::DrawLegend(HDC hdc, int x, int y) {
    SetTextColor(hdc, RGB(100, 100, 100));
    SetBkMode(hdc, TRANSPARENT);
    
    TextOutW(hdc, x, y, L"Edge thickness = duration", 24);
    
    // Draw sample edges
    HPEN thinPen = CreatePen(PS_SOLID, 1, RGB(100, 100, 100));
    HPEN thickPen = CreatePen(PS_SOLID, 5, RGB(100, 100, 100));
    
    SelectObject(hdc, thinPen);
    MoveToEx(hdc, x + 160, y + 6, nullptr);
    LineTo(hdc, x + 200, y + 6);
    TextOutW(hdc, x + 205, y, L"Fast", 4);
    
    SelectObject(hdc, thickPen);
    MoveToEx(hdc, x + 240, y + 6, nullptr);
    LineTo(hdc, x + 280, y + 6);
    TextOutW(hdc, x + 285, y, L"Slow", 4);
    
    DeleteObject(thinPen);
    DeleteObject(thickPen);
}

COLORREF GPUPipelineGraph::GetPipelineColor(uint32_t pipelineID) {
    // Generate color based on pipeline ID
    int hue = (pipelineID * 30) % 360;
    
    // Simple HSV to RGB conversion for hue only (S=0.5, V=0.9)
    int r, g, b;
    int sector = hue / 60;
    int remainder = (hue % 60) * 255 / 60;
    
    switch (sector) {
        case 0: r = 255; g = remainder; b = 0; break;
        case 1: r = 255 - remainder; g = 255; b = 0; break;
        case 2: r = 0; g = 255; b = remainder; break;
        case 3: r = 0; g = 255 - remainder; b = 255; break;
        case 4: r = remainder; g = 0; b = 255; break;
        default: r = 255; g = 0; b = 255 - remainder; break;
    }
    
    // Adjust saturation and value
    r = r * 0.5 + 115;
    g = g * 0.5 + 115;
    b = b * 0.5 + 115;
    
    return RGB(r, g, b);
}

int GPUPipelineGraph::GetLineThickness(uint64_t durationNs) {
    if (durationNs < 1000) return 1;
    if (durationNs < 10000) return 2;
    if (durationNs < 100000) return 3;
    if (durationNs < 1000000) return 4;
    return 5;
}

void GPUPipelineGraph::OnPaint() {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(m_hwnd, &ps);
    Render(hdc);
    EndPaint(m_hwnd, &ps);
}

LRESULT CALLBACK GPUPipelineGraph::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GPUPipelineGraph* graph = nullptr;
    
    if (msg == WM_CREATE) {
        auto cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        graph = reinterpret_cast<GPUPipelineGraph*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(graph));
    } else {
        graph = reinterpret_cast<GPUPipelineGraph*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    switch (msg) {
        case WM_PAINT:
            if (graph) graph->OnPaint();
            return 0;
            
        case WM_HSCROLL: {
            SCROLLINFO si = {};
            si.cbSize = sizeof(si);
            si.fMask = SIF_ALL;
            GetScrollInfo(hwnd, SB_HORZ, &si);
            
            int pos = si.nPos;
            switch (LOWORD(wParam)) {
                case SB_LINELEFT: pos -= 20; break;
                case SB_LINERIGHT: pos += 20; break;
                case SB_PAGELEFT: pos -= si.nPage; break;
                case SB_PAGERIGHT: pos += si.nPage; break;
                case SB_THUMBTRACK: pos = HIWORD(wParam); break;
            }
            
            si.fMask = SIF_POS;
            si.nPos = pos;
            SetScrollInfo(hwnd, SB_HORZ, &si, TRUE);
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
