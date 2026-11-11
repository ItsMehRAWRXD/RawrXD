// BreakpointsGutter.cpp
// Phase 24: The Cockpit - Breakpoint Margin Implementation
// ============================================================================

#include "ui/BreakpointsGutter.h"
#include "ui/Win32IDE_UI_EventBridge.h"
#include <unordered_map>

namespace RawrXD {
namespace UI {

// ============================================================================
// Implementation
// ============================================================================
class BreakpointsGutter::Impl {
public:
    HWND hwnd_ = nullptr;
    HWND parentWindow_ = nullptr;
    BreakpointGutterConfig config_;
    
    // Line number -> breakpoint state
    std::unordered_map<uint32_t, BreakpointVisualState> breakpointStates_;
    uint32_t currentLine_ = 0;
    bool hasCurrentLine_ = false;
    
    // Hover state
    uint32_t hoverLine_ = 0;
    bool hasHover_ = false;
    
    // Callback
    BreakpointToggleCallback toggleCallback_;
    
    // Drawing resources
    HBRUSH hbrEnabled_ = nullptr;
    HBRUSH hbrDisabled_ = nullptr;
    HBRUSH hbrHit_ = nullptr;
    HBRUSH hbrBackground_ = nullptr;
    HPEN hpenBorder_ = nullptr;
    
    void CreateBrushes() {
        hbrEnabled_ = CreateSolidBrush(config_.enabledColor);
        hbrDisabled_ = CreateSolidBrush(config_.disabledColor);
        hbrHit_ = CreateSolidBrush(config_.hitColor);
        hbrBackground_ = CreateSolidBrush(config_.backgroundColor);
        hpenBorder_ = CreatePen(PS_SOLID, 1, config_.borderColor);
    }
    
    void DestroyBrushes() {
        if (hbrEnabled_) DeleteObject(hbrEnabled_);
        if (hbrDisabled_) DeleteObject(hbrDisabled_);
        if (hbrHit_) DeleteObject(hbrHit_);
        if (hbrBackground_) DeleteObject(hbrBackground_);
        if (hpenBorder_) DeleteObject(hpenBorder_);
        hbrEnabled_ = hbrDisabled_ = hbrHit_ = hbrBackground_ = nullptr;
        hpenBorder_ = nullptr;
    }
    
    void DrawBreakpoint(HDC hdc, int centerX, int centerY, BreakpointVisualState state) {
        int radius = config_.breakpointSize / 2;
        
        switch (state) {
            case BreakpointVisualState::Enabled: {
                // Filled red circle
                HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, hbrEnabled_);
                HPEN oldPen = (HPEN)SelectObject(hdc, GetStockObject(NULL_PEN));
                Ellipse(hdc, centerX - radius, centerY - radius, 
                       centerX + radius, centerY + radius);
                SelectObject(hdc, oldBrush);
                SelectObject(hdc, oldPen);
                break;
            }
            
            case BreakpointVisualState::Disabled: {
                // Hollow gray circle
                HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
                HPEN oldPen = (HPEN)SelectObject(hdc, hbrDisabled_);
                Ellipse(hdc, centerX - radius, centerY - radius, 
                       centerX + radius, centerY + radius);
                SelectObject(hdc, oldBrush);
                SelectObject(hdc, oldPen);
                break;
            }
            
            case BreakpointVisualState::Hit: {
                // Yellow filled circle with red border
                HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, hbrHit_);
                HPEN oldPen = (HPEN)SelectObject(hdc, GetStockObject(NULL_PEN));
                Ellipse(hdc, centerX - radius, centerY - radius, 
                       centerX + radius, centerY + radius);
                SelectObject(hdc, oldBrush);
                SelectObject(hdc, oldPen);
                
                // Draw arrow pointing right
                POINT arrow[] = {
                    {centerX - 3, centerY - 4},
                    {centerX + 5, centerY},
                    {centerX - 3, centerY + 4}
                };
                HPEN arrowPen = CreatePen(PS_SOLID, 2, RGB(0, 0, 0));
                oldPen = (HPEN)SelectObject(hdc, arrowPen);
                Polygon(hdc, arrow, 3);
                SelectObject(hdc, oldPen);
                DeleteObject(arrowPen);
                break;
            }
            
            default:
                break;
        }
    }
    
    void DrawCurrentLineIndicator(HDC hdc, int centerX, int centerY) {
        // Draw yellow arrow pointing to current line
        int size = config_.breakpointSize / 2;
        POINT arrow[] = {
            {centerX - size + 2, centerY - size + 2},
            {centerX + 2, centerY},
            {centerX - size + 2, centerY + size - 2}
        };
        
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, hbrHit_);
        HPEN oldPen = (HPEN)SelectObject(hdc, GetStockObject(NULL_PEN));
        Polygon(hdc, arrow, 3);
        SelectObject(hdc, oldBrush);
        SelectObject(hdc, oldPen);
    }
};

BreakpointsGutter::BreakpointsGutter() : pImpl_(std::make_unique<Impl>()) {}
BreakpointsGutter::~BreakpointsGutter() = default;

bool BreakpointsGutter::Initialize(HWND parentWindow) {
    pImpl_->parentWindow_ = parentWindow;
    pImpl_->CreateBrushes();
    return true;
}

void BreakpointsGutter::Shutdown() {
    pImpl_->DestroyBrushes();
}

void BreakpointsGutter::SetConfig(const BreakpointGutterConfig& config) {
    pImpl_->DestroyBrushes();
    pImpl_->config_ = config;
    pImpl_->CreateBrushes();
}

const BreakpointGutterConfig& BreakpointsGutter::GetConfig() const {
    return pImpl_->config_;
}

void BreakpointsGutter::SetBreakpointState(uint32_t lineNumber, BreakpointVisualState state) {
    pImpl_->breakpointStates_[lineNumber] = state;
    Invalidate();
}

void BreakpointsGutter::ClearBreakpointState(uint32_t lineNumber) {
    pImpl_->breakpointStates_.erase(lineNumber);
    Invalidate();
}

void BreakpointsGutter::ClearAllBreakpoints() {
    pImpl_->breakpointStates_.clear();
    Invalidate();
}

void BreakpointsGutter::SetCurrentLine(uint32_t lineNumber) {
    pImpl_->currentLine_ = lineNumber;
    pImpl_->hasCurrentLine_ = true;
    Invalidate();
}

void BreakpointsGutter::ClearCurrentLine() {
    pImpl_->hasCurrentLine_ = false;
    Invalidate();
}

void BreakpointsGutter::Render(HDC hdc, const RECT& gutterRect, 
                                int firstVisibleLine, int linesVisible, int lineHeight) {
    // Fill background
    FillRect(hdc, &gutterRect, pImpl_->hbrBackground_);
    
    // Draw right border
    HPEN oldPen = (HPEN)SelectObject(hdc, pImpl_->hpenBorder_);
    MoveToEx(hdc, gutterRect.right - 1, gutterRect.top, nullptr);
    LineTo(hdc, gutterRect.right - 1, gutterRect.bottom);
    SelectObject(hdc, oldPen);
    
    // Calculate center X for breakpoint circles
    int centerX = (gutterRect.left + gutterRect.right) / 2;
    
    // Render breakpoints for visible lines
    for (int i = 0; i < linesVisible; i++) {
        uint32_t lineNum = firstVisibleLine + i;
        int centerY = gutterRect.top + (i * lineHeight) + (lineHeight / 2);
        
        // Check if this line has a breakpoint
        auto it = pImpl_->breakpointStates_.find(lineNum);
        if (it != pImpl_->breakpointStates_.end()) {
            pImpl_->DrawBreakpoint(hdc, centerX, centerY, it->second);
        }
        
        // Draw current line indicator
        if (pImpl_->hasCurrentLine_ && lineNum == pImpl_->currentLine_) {
            pImpl_->DrawCurrentLineIndicator(hdc, centerX, centerY);
        }
    }
}

void BreakpointsGutter::Invalidate() {
    if (pImpl_->hwnd_) {
        ::InvalidateRect(pImpl_->hwnd_, nullptr, TRUE);
    }
}

void BreakpointsGutter::SetBreakpointToggleCallback(BreakpointToggleCallback callback) {
    pImpl_->toggleCallback_ = callback;
}

bool BreakpointsGutter::OnMouseClick(int x, int y, const std::wstring& currentFile) {
    if (!IsInGutter(x)) return false;
    
    // Calculate line number from Y position
    // This requires knowing the editor's scroll position and line height
    // For now, return true to indicate we handled it
    
    if (pImpl_->toggleCallback_) {
        // Line number calculation would go here
        // pImpl_->toggleCallback_(currentFile, lineNumber);
    }
    
    return true;
}

bool BreakpointsGutter::OnMouseMove(int x, int y) {
    if (!IsInGutter(x)) {
        if (pImpl_->hasHover_) {
            pImpl_->hasHover_ = false;
            return true; // Need to redraw
        }
        return false;
    }
    
    // Calculate hover line
    // pImpl_->hoverLine_ = ...;
    pImpl_->hasHover_ = true;
    
    return true;
}

bool BreakpointsGutter::OnMouseLeave() {
    if (pImpl_->hasHover_) {
        pImpl_->hasHover_ = false;
        return true;
    }
    return false;
}

int BreakpointsGutter::LineFromPoint(int y, int firstVisibleLine, int lineHeight) const {
    int relativeY = y; // Would need to adjust for gutter rect
    int lineOffset = relativeY / lineHeight;
    return firstVisibleLine + lineOffset;
}

bool BreakpointsGutter::IsInGutter(int x) const {
    return x >= 0 && x < pImpl_->config_.width;
}

int BreakpointsGutter::GetWidth() const {
    return pImpl_->config_.width;
}

void BreakpointsGutter::SetWidth(int width) {
    pImpl_->config_.width = width;
}

} // namespace UI
} // namespace RawrXD
