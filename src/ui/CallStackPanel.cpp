// CallStackPanel.cpp
// Phase 24: The Cockpit - Call Stack Implementation
// ============================================================================

#include "ui/CallStackPanel.h"
#include "debugger/Debugger_Backend.h"
#include <algorithm>

namespace RawrXD {
namespace UI {

// ============================================================================
// Implementation
// ============================================================================
class CallStackPanel::Impl {
public:
    HWND hwnd_ = nullptr;
    HWND parentWindow_ = nullptr;
    CallStackPanelConfig config_;
    
    std::vector<CallStackDisplayFrame> frames_;
    size_t selectedFrame_ = 0;
    size_t currentFrame_ = 0;  // The actual current IP frame
    
    HFONT hFont_ = nullptr;
    HFONT hFontBold_ = nullptr;
    
    FrameSelectedCallback frameSelectedCallback_;
    
    int panelWidth_ = 400;
    int panelHeight_ = 300;
    
    void CreateFonts() {
        if (hFont_) DeleteObject(hFont_);
        if (hFontBold_) DeleteObject(hFontBold_);
        
        hFont_ = CreateFontW(
            config_.fontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_MODERN, config_.fontName
        );
        
        hFontBold_ = CreateFontW(
            config_.fontSize, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_MODERN, config_.fontName
        );
    }
    
    void DestroyFonts() {
        if (hFont_) {
            DeleteObject(hFont_);
            hFont_ = nullptr;
        }
        if (hFontBold_) {
            DeleteObject(hFontBold_);
            hFontBold_ = nullptr;
        }
    }
    
    void DrawFrame(HDC hdc, int y, const CallStackDisplayFrame& frame, bool isSelected) {
        RECT rowRect = { 0, y, panelWidth_, y + config_.rowHeight };
        
        // Background
        if (isSelected) {
            HBRUSH hbr = CreateSolidBrush(config_.selectedColor);
            FillRect(hdc, &rowRect, hbr);
            DeleteObject(hbr);
            SetTextColor(hdc, config_.selectedTextColor);
        } else {
            HBRUSH hbr = CreateSolidBrush(config_.backgroundColor);
            FillRect(hdc, &rowRect, hbr);
            DeleteObject(hbr);
            SetTextColor(hdc, config_.textColor);
        }
        
        // Set font
        HFONT hFont = frame.isCurrentFrame ? hFontBold_ : hFont_;
        HFONT oldFont = (HFONT)SelectObject(hdc, hFont);
        
        // Draw frame indicator for current frame
        int x = 5;
        if (frame.isCurrentFrame) {
            // Draw yellow arrow
            HBRUSH arrowBrush = CreateSolidBrush(config_.framePointerColor);
            HPEN oldPen = (HPEN)SelectObject(hdc, GetStockObject(NULL_PEN));
            HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, arrowBrush);
            
            POINT arrow[] = {
                {x, y + 5},
                {x + 8, y + config_.rowHeight / 2},
                {x, y + config_.rowHeight - 5}
            };
            Polygon(hdc, arrow, 3);
            
            SelectObject(hdc, oldPen);
            SelectObject(hdc, oldBrush);
            DeleteObject(arrowBrush);
            x += 15;
        } else {
            x += 15;  // Indent non-current frames
        }
        
        // Draw function name
        RECT textRect = { x, y, panelWidth_ - 5, y + config_.rowHeight };
        std::wstring displayText = frame.functionName;
        if (displayText.empty()) {
            // Show address if no symbol
            wchar_t addrStr[32];
            swprintf_s(addrStr, L"0x%016llX", frame.address);
            displayText = addrStr;
        }
        
        // Truncate if too long
        DrawTextW(hdc, displayText.c_str(), -1, &textRect, 
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        
        // Draw module name (right-aligned)
        if (!frame.moduleName.empty()) {
            RECT moduleRect = { panelWidth_ - 150, y, panelWidth_ - 5, y + config_.rowHeight };
            SetTextColor(hdc, isSelected ? RGB(200, 200, 200) : RGB(128, 128, 128));
            DrawTextW(hdc, frame.moduleName.c_str(), -1, &moduleRect,
                      DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        }
        
        // Draw line info (if available)
        if (frame.lineNumber > 0 && !frame.filePath.empty()) {
            RECT lineRect = { panelWidth_ - 300, y, panelWidth_ - 160, y + config_.rowHeight };
            std::wstring lineInfo = frame.filePath.substr(frame.filePath.find_last_of(L"\\/") + 1);
            lineInfo += L":" + std::to_wstring(frame.lineNumber);
            SetTextColor(hdc, isSelected ? RGB(180, 180, 180) : RGB(100, 100, 100));
            DrawTextW(hdc, lineInfo.c_str(), -1, &lineRect,
                      DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        }
        
        SelectObject(hdc, oldFont);
    }
};

CallStackPanel::CallStackPanel() : pImpl_(std::make_unique<Impl>()) {}
CallStackPanel::~CallStackPanel() = default;

bool CallStackPanel::Initialize(HWND parentWindow) {
    pImpl_->parentWindow_ = parentWindow;
    pImpl_->CreateFonts();
    return true;
}

void CallStackPanel::Shutdown() {
    pImpl_->DestroyFonts();
}

void CallStackPanel::SetConfig(const CallStackPanelConfig& config) {
    pImpl_->config_ = config;
    pImpl_->CreateFonts();
}

void CallStackPanel::UpdateCallStack(const std::vector<Debugger::StackFrame>& frames) {
    pImpl_->frames_.clear();
    
    for (size_t i = 0; i < frames.size(); i++) {
        CallStackDisplayFrame displayFrame;
        displayFrame.frameNumber = frames[i].frameNumber;
        displayFrame.functionName = frames[i].functionName;
        displayFrame.moduleName = frames[i].moduleName;
        displayFrame.filePath = frames[i].filePath;
        displayFrame.lineNumber = frames[i].lineNumber;
        displayFrame.address = frames[i].instructionPointer;
        displayFrame.isCurrentFrame = (i == 0);  // First frame is current
        pImpl_->frames_.push_back(displayFrame);
    }
    
    pImpl_->currentFrame_ = 0;
    pImpl_->selectedFrame_ = 0;
    Invalidate();
}

void CallStackPanel::ClearCallStack() {
    pImpl_->frames_.clear();
    pImpl_->selectedFrame_ = 0;
    pImpl_->currentFrame_ = 0;
    Invalidate();
}

void CallStackPanel::SetCurrentFrame(size_t frameIndex) {
    if (frameIndex < pImpl_->frames_.size()) {
        pImpl_->selectedFrame_ = frameIndex;
        Invalidate();
    }
}

void CallStackPanel::Render(HDC hdc, const RECT& panelRect) {
    // Fill background
    HBRUSH bgBrush = CreateSolidBrush(pImpl_->config_.backgroundColor);
    FillRect(hdc, &panelRect, bgBrush);
    DeleteObject(bgBrush);
    
    // Set background mode
    SetBkMode(hdc, TRANSPARENT);
    
    // Draw each frame
    int y = panelRect.top;
    for (size_t i = 0; i < pImpl_->frames_.size(); i++) {
        pImpl_->DrawFrame(hdc, y, pImpl_->frames_[i], i == pImpl_->selectedFrame_);
        y += pImpl_->config_.rowHeight;
        
        if (y > panelRect.bottom) break;
    }
}

void CallStackPanel::Invalidate() {
    if (pImpl_->hwnd_) {
        ::InvalidateRect(pImpl_->hwnd_, nullptr, TRUE);
    }
}

void CallStackPanel::SetFrameSelectedCallback(FrameSelectedCallback callback) {
    pImpl_->frameSelectedCallback_ = callback;
}

bool CallStackPanel::OnMouseClick(int x, int y) {
    size_t frameIndex = y / pImpl_->config_.rowHeight;
    if (frameIndex < pImpl_->frames_.size()) {
        pImpl_->selectedFrame_ = frameIndex;
        Invalidate();
        
        if (pImpl_->frameSelectedCallback_) {
            pImpl_->frameSelectedCallback_(frameIndex);
        }
        return true;
    }
    return false;
}

bool CallStackPanel::OnMouseDoubleClick(int x, int y) {
    // Same as click but could navigate to source
    return OnMouseClick(x, y);
}

bool CallStackPanel::OnKeyDown(WPARAM keyCode) {
    switch (keyCode) {
        case VK_UP:
            if (pImpl_->selectedFrame_ > 0) {
                pImpl_->selectedFrame_--;
                Invalidate();
                if (pImpl_->frameSelectedCallback_) {
                    pImpl_->frameSelectedCallback_(pImpl_->selectedFrame_);
                }
            }
            return true;
            
        case VK_DOWN:
            if (pImpl_->selectedFrame_ < pImpl_->frames_.size() - 1) {
                pImpl_->selectedFrame_++;
                Invalidate();
                if (pImpl_->frameSelectedCallback_) {
                    pImpl_->frameSelectedCallback_(pImpl_->selectedFrame_);
                }
            }
            return true;
            
        case VK_RETURN:
            if (pImpl_->frameSelectedCallback_) {
                pImpl_->frameSelectedCallback_(pImpl_->selectedFrame_);
            }
            return true;
    }
    return false;
}

SIZE CallStackPanel::GetPreferredSize() const {
    size_t frameCount = pImpl_->frames_.size();
    size_t minFrames = 5;
    size_t displayFrames = (frameCount > minFrames) ? frameCount : minFrames;
    return { 400, static_cast<LONG>(displayFrames * pImpl_->config_.rowHeight) };
}

void CallStackPanel::SetSize(int width, int height) {
    pImpl_->panelWidth_ = width;
    pImpl_->panelHeight_ = height;
}

} // namespace UI
} // namespace RawrXD
