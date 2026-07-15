// ProblemsPanel.cpp
// Phase 24: The Cockpit - Problems Panel Implementation
// ============================================================================

#include "ui/ProblemsPanel.h"
#include "lsp/LSP_Diagnostics.h"
#include <algorithm>

namespace RawrXD {
namespace UI {

// ============================================================================
// Implementation
// ============================================================================
class ProblemsPanel::Impl {
public:
    HWND hwnd_ = nullptr;
    HWND parentWindow_ = nullptr;
    ProblemsPanelConfig config_;
    
    // All diagnostics grouped by file
    std::vector<ProblemDisplayItem> allProblems_;
    std::vector<ProblemDisplayItem> filteredProblems_;
    size_t selectedIndex_ = 0;
    
    HFONT hFont_ = nullptr;
    HFONT hFontBold_ = nullptr;
    
    ProblemSelectedCallback selectedCallback_;
    
    int panelWidth_ = 600;
    int panelHeight_ = 200;
    
    void CreateFonts() {
        if (hFont_) DeleteObject(hFont_);
        if (hFontBold_) DeleteObject(hFontBold_);
        
        hFont_ = CreateFontW(
            config_.fontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, config_.fontName
        );
        
        hFontBold_ = CreateFontW(
            config_.fontSize, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, config_.fontName
        );
    }
    
    void DestroyFonts() {
        if (hFont_) { DeleteObject(hFont_); hFont_ = nullptr; }
        if (hFontBold_) { DeleteObject(hFontBold_); hFontBold_ = nullptr; }
    }
    
    bool ShouldShowSeverity(LSP::DiagnosticSeverity severity) const {
        switch (severity) {
            case LSP::DiagnosticSeverity::Error: return config_.showErrors;
            case LSP::DiagnosticSeverity::Warning: return config_.showWarnings;
            case LSP::DiagnosticSeverity::Information: return config_.showInfo;
            case LSP::DiagnosticSeverity::Hint: return config_.showHints;
            default: return true;
        }
    }
    
    COLORREF GetSeverityColor(LSP::DiagnosticSeverity severity) const {
        switch (severity) {
            case LSP::DiagnosticSeverity::Error: return config_.errorColor;
            case LSP::DiagnosticSeverity::Warning: return config_.warningColor;
            case LSP::DiagnosticSeverity::Information: return config_.infoColor;
            case LSP::DiagnosticSeverity::Hint: return config_.hintColor;
            default: return config_.infoColor;
        }
    }
    
    void DrawProblem(HDC hdc, int y, const ProblemDisplayItem& problem, bool isSelected) {
        RECT rowRect = { 0, y, panelWidth_, y + config_.rowHeight };
        
        // Background
        if (isSelected) {
            HBRUSH hbr = CreateSolidBrush(config_.selectedBackground);
            FillRect(hdc, &rowRect, hbr);
            DeleteObject(hbr);
            SetTextColor(hdc, config_.selectedText);
        } else {
            HBRUSH hbr = CreateSolidBrush(config_.backgroundColor);
            FillRect(hdc, &rowRect, hbr);
            DeleteObject(hbr);
            SetTextColor(hdc, RGB(0, 0, 0));
        }
        
        HFONT oldFont = (HFONT)SelectObject(hdc, hFont_);
        SetBkMode(hdc, TRANSPARENT);
        
        // Draw severity icon
        int iconX = 5;
        int iconY = y + (config_.rowHeight - 12) / 2;
        COLORREF severityColor = GetSeverityColor(problem.severity);
        
        HBRUSH iconBrush = CreateSolidBrush(severityColor);
        HPEN oldPen = (HPEN)SelectObject(hdc, GetStockObject(NULL_PEN));
        HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, iconBrush);
        
        // Draw circle for severity
        Ellipse(hdc, iconX, iconY, iconX + 12, iconY + 12);
        
        SelectObject(hdc, oldPen);
        SelectObject(hdc, oldBrush);
        DeleteObject(iconBrush);
        
        // Draw file name and line
        int textX = iconX + 20;
        RECT fileRect = { textX, y, textX + 200, y + config_.rowHeight };
        std::wstring fileName = problem.filePath.substr(problem.filePath.find_last_of(L"\\/") + 1);
        fileName += L":" + std::to_wstring(problem.lineNumber);
        DrawTextW(hdc, fileName.c_str(), -1, &fileRect, 
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        
        // Draw message
        RECT msgRect = { textX + 210, y, panelWidth_ - 5, y + config_.rowHeight };
        DrawTextW(hdc, problem.message.c_str(), -1, &msgRect,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        
        SelectObject(hdc, oldFont);
    }
    
    void ApplyFilter() {
        filteredProblems_.clear();
        for (const auto& problem : allProblems_) {
            if (ShouldShowSeverity(problem.severity)) {
                filteredProblems_.push_back(problem);
            }
        }
        
        // Sort by severity (errors first) then by file/line
        std::sort(filteredProblems_.begin(), filteredProblems_.end(),
            [](const ProblemDisplayItem& a, const ProblemDisplayItem& b) {
                if (a.severity != b.severity) {
                    return static_cast<int>(a.severity) < static_cast<int>(b.severity);
                }
                if (a.filePath != b.filePath) {
                    return a.filePath < b.filePath;
                }
                return a.lineNumber < b.lineNumber;
            });
    }
};

ProblemsPanel::ProblemsPanel() : pImpl_(std::make_unique<Impl>()) {}
ProblemsPanel::~ProblemsPanel() = default;

bool ProblemsPanel::Initialize(HWND parentWindow) {
    pImpl_->parentWindow_ = parentWindow;
    pImpl_->CreateFonts();
    return true;
}

void ProblemsPanel::Shutdown() {
    pImpl_->DestroyFonts();
}

void ProblemsPanel::SetConfig(const ProblemsPanelConfig& config) {
    pImpl_->config_ = config;
    pImpl_->CreateFonts();
}

void ProblemsPanel::SetFilter(bool errors, bool warnings, bool info, bool hints) {
    pImpl_->config_.showErrors = errors;
    pImpl_->config_.showWarnings = warnings;
    pImpl_->config_.showInfo = info;
    pImpl_->config_.showHints = hints;
    pImpl_->ApplyFilter();
    Invalidate();
}

void ProblemsPanel::AddDiagnostic(const std::wstring& filePath, const LSP::Diagnostic& diagnostic) {
    ProblemDisplayItem item;
    item.filePath = filePath;
    item.lineNumber = diagnostic.range.start.line + 1;  // LSP is 0-based
    item.column = diagnostic.range.start.character + 1;
    item.message = diagnostic.message;
    item.code = diagnostic.code;
    item.severity = diagnostic.severity;
    
    pImpl_->allProblems_.push_back(item);
    pImpl_->ApplyFilter();
}

void ProblemsPanel::ClearDiagnostics(const std::wstring& filePath) {
    pImpl_->allProblems_.erase(
        std::remove_if(pImpl_->allProblems_.begin(), pImpl_->allProblems_.end(),
            [&filePath](const ProblemDisplayItem& item) {
                return item.filePath == filePath;
            }),
        pImpl_->allProblems_.end()
    );
    pImpl_->ApplyFilter();
}

void ProblemsPanel::ClearAllDiagnostics() {
    pImpl_->allProblems_.clear();
    pImpl_->filteredProblems_.clear();
    pImpl_->selectedIndex_ = 0;
}

void ProblemsPanel::RefreshDisplay() {
    pImpl_->ApplyFilter();
    Invalidate();
}

void ProblemsPanel::Render(HDC hdc, const RECT& panelRect) {
    // Fill background
    HBRUSH bgBrush = CreateSolidBrush(pImpl_->config_.backgroundColor);
    FillRect(hdc, &panelRect, bgBrush);
    DeleteObject(bgBrush);
    
    // Draw header with counts
    RECT headerRect = { panelRect.left, panelRect.top, panelRect.right, panelRect.top + 25 };
    HBRUSH headerBrush = CreateSolidBrush(RGB(240, 240, 240));
    FillRect(hdc, &headerRect, headerBrush);
    DeleteObject(headerBrush);
    
    HFONT oldFont = (HFONT)SelectObject(hdc, pImpl_->hFontBold_);
    SetTextColor(hdc, RGB(0, 0, 0));
    SetBkMode(hdc, TRANSPARENT);
    
    wchar_t headerText[256];
    swprintf_s(headerText, L"Problems: %zu errors, %zu warnings, %zu info",
               GetErrorCount(), GetWarningCount(), GetInfoCount());
    
    RECT textRect = { headerRect.left + 10, headerRect.top, headerRect.right, headerRect.bottom };
    DrawTextW(hdc, headerText, -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, oldFont);
    
    // Draw separator line
    HPEN linePen = CreatePen(PS_SOLID, 1, RGB(200, 200, 200));
    HPEN oldPen = (HPEN)SelectObject(hdc, linePen);
    MoveToEx(hdc, panelRect.left, panelRect.top + 25, nullptr);
    LineTo(hdc, panelRect.right, panelRect.top + 25);
    SelectObject(hdc, oldPen);
    DeleteObject(linePen);
    
    // Draw problems
    int y = panelRect.top + 30;
    for (size_t i = 0; i < pImpl_->filteredProblems_.size() && y < panelRect.bottom; i++) {
        pImpl_->DrawProblem(hdc, y, pImpl_->filteredProblems_[i], i == pImpl_->selectedIndex_);
        y += pImpl_->config_.rowHeight;
    }
}

void ProblemsPanel::Invalidate() {
    if (pImpl_->hwnd_) {
        ::InvalidateRect(pImpl_->hwnd_, nullptr, TRUE);
    }
}

void ProblemsPanel::SetProblemSelectedCallback(ProblemSelectedCallback callback) {
    pImpl_->selectedCallback_ = callback;
}

bool ProblemsPanel::OnMouseClick(int x, int y) {
    // Account for header
    if (y < 30) return false;
    
    size_t index = (y - 30) / pImpl_->config_.rowHeight;
    if (index < pImpl_->filteredProblems_.size()) {
        pImpl_->selectedIndex_ = index;
        Invalidate();
        return true;
    }
    return false;
}

bool ProblemsPanel::OnMouseDoubleClick(int x, int y) {
    if (OnMouseClick(x, y)) {
        if (pImpl_->selectedCallback_ && pImpl_->selectedIndex_ < pImpl_->filteredProblems_.size()) {
            const auto& problem = pImpl_->filteredProblems_[pImpl_->selectedIndex_];
            pImpl_->selectedCallback_(problem.filePath, problem.lineNumber, problem.column);
        }
        return true;
    }
    return false;
}

bool ProblemsPanel::OnKeyDown(WPARAM keyCode) {
    switch (keyCode) {
        case VK_UP:
            if (pImpl_->selectedIndex_ > 0) {
                pImpl_->selectedIndex_--;
                Invalidate();
            }
            return true;
            
        case VK_DOWN:
            if (pImpl_->selectedIndex_ < pImpl_->filteredProblems_.size() - 1) {
                pImpl_->selectedIndex_++;
                Invalidate();
            }
            return true;
            
        case VK_RETURN:
            if (pImpl_->selectedCallback_ && pImpl_->selectedIndex_ < pImpl_->filteredProblems_.size()) {
                const auto& problem = pImpl_->filteredProblems_[pImpl_->selectedIndex_];
                pImpl_->selectedCallback_(problem.filePath, problem.lineNumber, problem.column);
            }
            return true;
    }
    return false;
}

size_t ProblemsPanel::GetErrorCount() const {
    return std::count_if(pImpl_->allProblems_.begin(), pImpl_->allProblems_.end(),
        [](const ProblemDisplayItem& item) {
            return item.severity == LSP::DiagnosticSeverity::Error;
        });
}

size_t ProblemsPanel::GetWarningCount() const {
    return std::count_if(pImpl_->allProblems_.begin(), pImpl_->allProblems_.end(),
        [](const ProblemDisplayItem& item) {
            return item.severity == LSP::DiagnosticSeverity::Warning;
        });
}

size_t ProblemsPanel::GetInfoCount() const {
    return std::count_if(pImpl_->allProblems_.begin(), pImpl_->allProblems_.end(),
        [](const ProblemDisplayItem& item) {
            return item.severity == LSP::DiagnosticSeverity::Information;
        });
}

size_t ProblemsPanel::GetTotalCount() const {
    return pImpl_->filteredProblems_.size();
}

SIZE ProblemsPanel::GetPreferredSize() const {
    return { 600, 200 };
}

void ProblemsPanel::SetSize(int width, int height) {
    pImpl_->panelWidth_ = width;
    pImpl_->panelHeight_ = height;
}

} // namespace UI
} // namespace RawrXD
