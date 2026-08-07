// GhostTextRenderer.cpp
// RawrXD Win32IDE Ghost Text Overlay Renderer
// Non-blocking, alpha-blended, GDI+ based

#include "GhostTextRenderer.h"
#include <windowsx.h>
#include <algorithm>

// ─── Constants ───
static constexpr COLORREF GHOST_TEXT_COLOR = RGB(128, 128, 128);      // Gray
static constexpr COLORREF GHOST_TEXT_HIGHLIGHT = RGB(147, 112, 219); // Purple
static constexpr int WM_GHOSTTEXT_UPDATE = WM_USER + 0x7001;
static constexpr int WM_GHOSTTEXT_CLEAR = WM_USER + 0x7002;

// ─── Construction / Destruction ───

GhostTextRenderer::GhostTextRenderer() noexcept
    : m_hwnd(nullptr)
    , m_hFont(nullptr)
    , m_lineHeight(0)
    , m_charWidth(0)
    , m_visible(false)
    , m_insertLine(0)
    , m_insertCol(0)
    , m_confidence(0)
{
    ZeroMemory(&m_textMetrics, sizeof(m_textMetrics));
}

GhostTextRenderer::~GhostTextRenderer() {
    Shutdown();
}

// ─── Initialization ───

bool GhostTextRenderer::Initialize(HWND hwnd, HFONT hFont) {
    if (!hwnd || !hFont) return false;
    
    m_hwnd = hwnd;
    m_hFont = hFont;
    
    // Get font metrics
    HDC hdc = GetDC(hwnd);
    if (hdc) {
        HFONT oldFont = (HFONT)SelectObject(hdc, hFont);
        GetTextMetricsW(hdc, &m_textMetrics);
        
        // Calculate average char width
        SIZE size;
        GetTextExtentPoint32W(hdc, L"M", 1, &size);
        m_charWidth = size.cx;
        m_lineHeight = m_textMetrics.tmHeight + m_textMetrics.tmExternalLeading;
        
        SelectObject(hdc, oldFont);
        ReleaseDC(hwnd, hdc);
    }
    
    return true;
}

void GhostTextRenderer::Shutdown() noexcept {
    Clear();
    m_hwnd = nullptr;
    m_hFont = nullptr;
}

// ─── Ghost Text Management ───

void GhostTextRenderer::ShowGhostText(
    const std::string& text,
    uint32_t line,
    uint32_t col,
    uint32_t confidence
) {
    if (!m_hwnd) return;
    
    // Convert UTF-8 to wide string
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (wideLen > 0) {
        m_ghostText.resize(wideLen);
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, m_ghostText.data(), wideLen);
        // Remove null terminator from string
        if (!m_ghostText.empty() && m_ghostText.back() == L'\0') {
            m_ghostText.pop_back();
        }
    }
    
    m_insertLine = line;
    m_insertCol = col;
    m_confidence = confidence;
    m_visible = true;
    
    // Post update message to trigger redraw
    PostMessageW(m_hwnd, WM_GHOSTTEXT_UPDATE, 0, 0);
}

void GhostTextRenderer::Clear() noexcept {
    m_ghostText.clear();
    m_visible = false;
    m_confidence = 0;
    
    if (m_hwnd) {
        PostMessageW(m_hwnd, WM_GHOSTTEXT_CLEAR, 0, 0);
    }
}

void GhostTextRenderer::UpdatePosition(uint32_t line, uint32_t col) {
    m_insertLine = line;
    m_insertCol = col;
    
    if (m_visible && m_hwnd) {
        InvalidateRect(m_hwnd, nullptr, FALSE);
    }
}

// ─── Rendering ───

void GhostTextRenderer::Render(HDC hdc) {
    if (!m_visible || m_ghostText.empty() || !m_hFont) return;
    
    // Save DC state
    int savedDC = SaveDC(hdc);
    
    // Set up font
    SelectObject(hdc, m_hFont);
    SetBkMode(hdc, TRANSPARENT);
    
    // Calculate position
    int x = m_insertCol * m_charWidth;
    int y = m_insertLine * m_lineHeight;
    
    // Choose color based on confidence
    COLORREF color = (m_confidence > 8000) ? GHOST_TEXT_HIGHLIGHT : GHOST_TEXT_COLOR;
    SetTextColor(hdc, color);
    
    // Draw ghost text with slight alpha effect (simulated with gray)
    RECT rect;
    rect.left = x;
    rect.top = y;
    rect.right = x + (m_ghostText.length() * m_charWidth);
    rect.bottom = y + m_lineHeight;
    
    // Draw with italic style for ghost appearance
    DrawTextW(hdc, m_ghostText.c_str(), static_cast<int>(m_ghostText.length()), 
              &rect, DT_LEFT | DT_TOP | DT_NOCLIP);
    
    // Restore DC
    RestoreDC(hdc, savedDC);
}

void GhostTextRenderer::GetGhostTextRect(RECT& outRect) const {
    if (!m_visible || m_ghostText.empty()) {
        SetRectEmpty(&outRect);
        return;
    }
    
    outRect.left = m_insertCol * m_charWidth;
    outRect.top = m_insertLine * m_lineHeight;
    outRect.right = outRect.left + (static_cast<int>(m_ghostText.length()) * m_charWidth);
    outRect.bottom = outRect.top + m_lineHeight;
}

// ─── Message Handlers ───

bool GhostTextRenderer::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_GHOSTTEXT_UPDATE:
            if (m_hwnd) {
                InvalidateRect(m_hwnd, nullptr, FALSE);
            }
            return true;
            
        case WM_GHOSTTEXT_CLEAR:
            if (m_hwnd) {
                InvalidateRect(m_hwnd, nullptr, FALSE);
            }
            return true;
            
        case WM_PAINT: {
            // Let default paint happen first, then overlay ghost text
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(m_hwnd, &ps);
            Render(hdc);
            EndPaint(m_hwnd, &ps);
            return false; // Let default handler also run
        }
    }
    
    return false;
}

// ─── Commit/Reject ───

std::wstring GhostTextRenderer::Commit() {
    std::wstring result = m_ghostText;
    Clear();
    return result;
}

void GhostTextRenderer::Reject() {
    Clear();
}

bool GhostTextRenderer::IsVisible() const noexcept {
    return m_visible && !m_ghostText.empty();
}
