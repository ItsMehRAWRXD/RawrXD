// ============================================================================
// GhostOverlay.cpp - Inline Diff Preview Implementation
// ============================================================================

#include "GhostOverlay.h"
#include <string>

namespace RawrXD {
namespace UI {

GhostOverlay::GhostOverlay() = default;
GhostOverlay::~GhostOverlay() { Detach(); }

bool GhostOverlay::Attach(HWND hEditor) {
    if (m_attached || !hEditor) return false;
    
    m_editor = hEditor;
    m_origProc = (WNDPROC)SetWindowLongPtr(hEditor, GWLP_WNDPROC, (LONG_PTR)SubclassProc);
    
    // Store this pointer in window data for callback access
    SetWindowLongPtr(hEditor, GWLP_USERDATA, (LONG_PTR)this);
    
    m_attached = true;
    return true;
}

void GhostOverlay::Detach() {
    if (!m_attached || !m_editor) return;
    
    SetWindowLongPtr(m_editor, GWLP_WNDPROC, (LONG_PTR)m_origProc);
    m_editor = nullptr;
    m_origProc = nullptr;
    m_attached = false;
}

void GhostOverlay::SetSuggestion(const GhostSuggestion& suggestion) {
    // Stale suggestion protection: reject older generation IDs
    if (suggestion.generation_id < m_suggestion.generation_id && m_suggestion.active) {
        // Late-arriving suggestion from older generation - discard
        // Record stale telemetry
        RawrXD::GhostTextTelemetry telemetry;
        telemetry.generation_id = suggestion.generation_id;
        telemetry.event = RawrXD::GhostTextEvent::STALE;
        telemetry.chars_shown = suggestion.text.length();
        RawrXD::GhostText_RecordTelemetry(telemetry);
        return;
    }
    
    m_suggestion = suggestion;
    m_suggestion.active = true;
    
    // Record SHOWN telemetry
    RawrXD::GhostTextTelemetry telemetry;
    telemetry.generation_id = m_suggestion.generation_id;
    telemetry.event = RawrXD::GhostTextEvent::SHOWN;
    telemetry.chars_shown = m_suggestion.text.length();
    RawrXD::GhostText_RecordTelemetry(telemetry);
    
    // Start fade-in animation
    StartAnimation();
    
    if (m_editor) {
        InvalidateRect(m_editor, nullptr, TRUE);
    }
}

void GhostOverlay::StartAnimation() {
    m_animation.startTime = GetTickCount64();
    m_animation.isAnimating = true;
    m_animation.currentAlpha = 0;
    
    // Set up timer for animation updates
    if (m_editor) {
        SetTimer(m_editor, kAnimationTimerId, kAnimationIntervalMs, nullptr);
    }
}

uint8_t GhostOverlay::CalculateCurrentAlpha() {
    if (!m_animation.isAnimating) {
        return 255;  // Fully opaque
    }
    
    uint64_t elapsed = GetTickCount64() - m_animation.startTime;
    if (elapsed >= m_animation.durationMs) {
        m_animation.isAnimating = false;
        m_animation.currentAlpha = 255;
        // Kill timer
        if (m_editor) {
            KillTimer(m_editor, kAnimationTimerId);
        }
        return 255;
    }
    
    // Linear interpolation from 0 to 255
    m_animation.currentAlpha = static_cast<uint8_t>((elapsed * 255) / m_animation.durationMs);
    return m_animation.currentAlpha;
}

void GhostOverlay::ClearSuggestion() {
    m_suggestion.active = false;
    if (m_editor) {
        InvalidateRect(m_editor, nullptr, TRUE);
    }
}

void GhostOverlay::Accept() {
    ApplySuggestion();
}

void GhostOverlay::Reject() {
    RejectSuggestion();
}

std::wstring GhostOverlay::GetStatusText() const {
    if (!m_suggestion.active) return L"";
    
    switch (m_suggestion.type) {
    case GhostType::Insert:
        return L"[Ghost] Insert: Tab=Accept, Esc=Reject";
    case GhostType::Replace:
        return L"[Ghost] Replace: Tab=Accept, Esc=Reject";
    case GhostType::Delete:
        return L"[Ghost] Delete: Tab=Accept, Esc=Reject";
    }
    return L"";
}

LRESULT CALLBACK GhostOverlay::SubclassProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GhostOverlay* self = (GhostOverlay*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
    if (!self) {
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    
    switch (msg) {
    case WM_PAINT: {
        // Let editor paint first
        LRESULT res = CallWindowProc(self->m_origProc, hWnd, msg, wParam, lParam);
        
        // Then draw ghost overlay
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        self->DrawGhost(hdc);
        EndPaint(hWnd, &ps);
        
        return res;
    }
    
    case WM_KEYDOWN: {
        if (self->m_suggestion.active) {
            // Tab acceptance with modifier protection
            if (wParam == VK_TAB) {
                // Only accept on plain Tab, not Shift+Tab or Ctrl+Tab
                bool shiftPressed = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
                bool ctrlPressed = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
                
                if (!shiftPressed && !ctrlPressed) {
                    // Plain Tab - accept suggestion
                    self->ApplySuggestion();
                    return 0; // Swallow Tab
                }
                // Shift+Tab or Ctrl+Tab - fall through for normal editor behavior
            }
            
            // Escape rejection
            if (wParam == VK_ESCAPE) {
                self->RejectSuggestion();
                return 0; // Swallow Esc
            }
            
            // Arrow keys dismiss suggestion (caret movement)
            if (wParam == VK_LEFT || wParam == VK_RIGHT || 
                wParam == VK_UP || wParam == VK_DOWN ||
                wParam == VK_HOME || wParam == VK_END ||
                wParam == VK_PRIOR || wParam == VK_NEXT) {  // Page Up/Down
                self->ExpireSuggestion();
                // Fall through to let editor handle the navigation
            }
            
            // Backspace dismisses suggestion
            if (wParam == VK_BACK) {
                self->ExpireSuggestion();
                // Fall through to let editor handle backspace
            }
        }
        break;
    }
    
    case WM_CHAR: {
        // Typing cancels suggestion with smart prefix matching
        if (self->m_suggestion.active && self->m_suggestion.type == GhostType::Insert) {
            wchar_t ch = static_cast<wchar_t>(wParam);
            
            // Check if character is printable (not control character)
            if (ch >= 0x20 && ch != 0x7F) {  // Not DEL, not control
                // Dismiss suggestion on any printable character
                self->ExpireSuggestion();
                // Fall through to let character be typed
            }
        } else if (self->m_suggestion.active) {
            // For Replace/Delete types, always dismiss on typing
            self->ExpireSuggestion();
        }
        break;
    }
    
    case WM_LBUTTONDOWN:
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN: {
        // Mouse click dismisses suggestion (caret moved)
        if (self->m_suggestion.active) {
            self->ExpireSuggestion();
        }
        break;
    }
    }
    
    return CallWindowProc(self->m_origProc, hWnd, msg, wParam, lParam);
}

void GhostOverlay::DrawGhost(HDC hdc) {
    if (!m_suggestion.active) return;
    
    POINT pt = GetCaretPixelPos();
    
    SetBkMode(hdc, TRANSPARENT);
    
    // Calculate current alpha for fade-in animation
    uint8_t alpha = CalculateCurrentAlpha();
    
    // Get font metrics for multi-line spacing
    TEXTMETRICW tm;
    GetTextMetricsW(hdc, &tm);
    int lineHeight = tm.tmHeight + tm.tmExternalLeading;
    
    if (m_suggestion.isMultiFile) {
        SetTextColor(hdc, kColorMultiFile);
        std::wstring text = L"[Patch: " + m_suggestion.filePath + L"] " + m_suggestion.text;
        
        // Multi-line support for multi-file patches
        RECT drawRect = { pt.x, pt.y, pt.x + 800, pt.y + 600 }; // Max width/height
        DrawTextExW(hdc, const_cast<LPWSTR>(text.c_str()), (int)text.length(), 
                    &drawRect, DT_LEFT | DT_TOP | DT_WORDBREAK | DT_NOPREFIX, nullptr);
        return;
    }
    
    switch (m_suggestion.type) {
    case GhostType::Insert:
        SetTextColor(hdc, kColorInsert);
        DrawMultiLineGhost(hdc, pt.x, pt.y, lineHeight, m_suggestion.text);
        break;
        
    case GhostType::Replace: {
        SetTextColor(hdc, kColorReplace);
        // Draw strikethrough on original
        if (!m_suggestion.original.empty()) {
            SIZE origSize;
            GetTextExtentPoint32W(hdc, m_suggestion.original.c_str(), (int)m_suggestion.original.length(), &origSize);
            
            // Draw original with strikethrough
            SetTextColor(hdc, kColorDelete);
            TextOutW(hdc, pt.x, pt.y, m_suggestion.original.c_str(), (int)m_suggestion.original.length());
            
            // Strikethrough line
            HPEN pen = CreatePen(PS_SOLID, 1, kColorDelete);
            HPEN oldPen = (HPEN)SelectObject(hdc, pen);
            MoveToEx(hdc, pt.x, pt.y + origSize.cy / 2, nullptr);
            LineTo(hdc, pt.x + origSize.cx, pt.y + origSize.cy / 2);
            SelectObject(hdc, oldPen);
            DeleteObject(pen);
            
            // Draw replacement after (with multi-line support)
            SetTextColor(hdc, kColorReplace);
            DrawMultiLineGhost(hdc, pt.x + origSize.cx + 10, pt.y, lineHeight, m_suggestion.text);
        } else {
            DrawMultiLineGhost(hdc, pt.x, pt.y, lineHeight, m_suggestion.text);
        }
        break;
    }
    
    case GhostType::Delete:
        SetTextColor(hdc, kColorDelete);
        DrawMultiLineGhost(hdc, pt.x, pt.y, lineHeight, m_suggestion.text);
        break;
    }
}

void GhostOverlay::DrawMultiLineGhost(HDC hdc, int x, int y, int lineHeight, const std::wstring& text) {
    // Split text by newlines and draw each line
    size_t start = 0;
    size_t end = 0;
    int currentY = y;
    
    while ((end = text.find(L'\n', start)) != std::wstring::npos) {
        std::wstring line = text.substr(start, end - start);
        if (!line.empty()) {
            TextOutW(hdc, x, currentY, line.c_str(), (int)line.length());
        }
        currentY += lineHeight;
        start = end + 1;
    }
    
    // Draw final line (or entire text if no newlines)
    std::wstring finalLine = text.substr(start);
    if (!finalLine.empty()) {
        TextOutW(hdc, x, currentY, finalLine.c_str(), (int)finalLine.length());
    }
}

void GhostOverlay::ApplySuggestion() {
    if (!m_suggestion.active || !m_editor) return;
    
    // Record telemetry
    RawrXD::GhostTextTelemetry telemetry;
    telemetry.generation_id = m_suggestion.generation_id;
    telemetry.event = RawrXD::GhostTextEvent::ACCEPTED;
    telemetry.chars_shown = m_suggestion.text.length();
    telemetry.chars_accepted = m_suggestion.text.length();
    RawrXD::GhostText_RecordTelemetry(telemetry);
    
    // Replace selection with suggestion text
    SendMessageW(m_editor, EM_REPLACESEL, TRUE, (LPARAM)m_suggestion.text.c_str());
    
    m_suggestion.active = false;
    InvalidateRect(m_editor, nullptr, TRUE);
}

void GhostOverlay::RejectSuggestion() {
    // Record telemetry
    RawrXD::GhostTextTelemetry telemetry;
    telemetry.generation_id = m_suggestion.generation_id;
    telemetry.event = RawrXD::GhostTextEvent::REJECTED;
    telemetry.chars_shown = m_suggestion.text.length();
    telemetry.chars_accepted = 0;
    RawrXD::GhostText_RecordTelemetry(telemetry);
    
    m_suggestion.active = false;
    m_suggestion.generation_id = 0;  // Reset generation ID
    if (m_editor) {
        InvalidateRect(m_editor, nullptr, TRUE);
    }
}

void GhostOverlay::ExpireSuggestion() {
    // Record telemetry for expired (typing/navigation dismissal)
    RawrXD::GhostTextTelemetry telemetry;
    telemetry.generation_id = m_suggestion.generation_id;
    telemetry.event = RawrXD::GhostTextEvent::EXPIRED;
    telemetry.chars_shown = m_suggestion.text.length();
    telemetry.chars_accepted = 0;
    RawrXD::GhostText_RecordTelemetry(telemetry);
    
    m_suggestion.active = false;
    m_suggestion.generation_id = 0;
    if (m_editor) {
        InvalidateRect(m_editor, nullptr, TRUE);
    }
}

POINT GhostOverlay::GetCaretPixelPos() {
    POINT pt = { 0, 0 };
    if (!m_editor) return pt;
    
    // Get caret position
    DWORD sel = SendMessage(m_editor, EM_GETSEL, 0, 0);
    int caretIndex = LOWORD(sel);
    
    int line = SendMessage(m_editor, EM_LINEFROMCHAR, caretIndex, 0);
    int lineIndex = SendMessage(m_editor, EM_LINEINDEX, line, 0);
    int col = caretIndex - lineIndex;
    
    // Get font metrics
    HDC hdc = GetDC(m_editor);
    HFONT font = (HFONT)SendMessage(m_editor, WM_GETFONT, 0, 0);
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    
    // Measure text up to column
    std::wstring text(col, L'X');
    SIZE sz;
    GetTextExtentPoint32W(hdc, text.c_str(), col, &sz);
    
    int lineHeight = GetLineHeight(hdc);
    
    SelectObject(hdc, oldFont);
    ReleaseDC(m_editor, hdc);
    
    // Get editor scroll position
    int firstVisible = SendMessage(m_editor, EM_GETFIRSTVISIBLELINE, 0, 0);
    
    pt.x = sz.cx + 4;
    pt.y = (line - firstVisible) * lineHeight + 2;
    
    return pt;
}

int GhostOverlay::GetLineHeight(HDC hdc) {
    TEXTMETRIC tm{};
    GetTextMetrics(hdc, &tm);
    return tm.tmHeight;
}

} // namespace UI
} // namespace RawrXD
