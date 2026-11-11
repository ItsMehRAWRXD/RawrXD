// ============================================================================
// Phase 27: Watch Expressions Panel Implementation
// ============================================================================

#include "WatchExpressionsPanel.hpp"
#include <windowsx.h>
#include <algorithm>
#include <sstream>
#include <fstream>

namespace RawrXD {
namespace UI {

// ============================================================================
// WatchExpressionsPanel::Impl
// ============================================================================

class WatchExpressionsPanel::Impl {
public:
    HWND m_hwnd = nullptr;
    HWND m_parent = nullptr;
    WatchPanelConfig m_config;
    
    // Data
    std::vector<std::shared_ptr<WatchExpression>> m_expressions;
    std::shared_ptr<WatchExpression> m_selectedExpression;
    std::shared_ptr<WatchExpression> m_editingExpression;
    
    // Layout
    int m_width = 400;
    int m_height = 300;
    int m_scrollOffset = 0;
    
    // Callbacks
    ExpressionSelectedCallback m_onSelect;
    EvaluateExpressionCallback m_onEvaluate;
    ExpressionAddedCallback m_onAdd;
    ExpressionRemovedCallback m_onRemove;
    
    // State
    uint32_t m_nextId = 1;
    HFONT m_hFont = nullptr;
    std::wstring m_editBuffer;
    bool m_isEditing = false;

    Impl() = default;
    ~Impl() {
        if (m_hFont) DeleteObject(m_hFont);
    }

    void CreateFont() {
        if (m_hFont) DeleteObject(m_hFont);
        m_hFont = CreateFontW(
            m_config.fontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, m_config.fontName
        );
    }

    std::shared_ptr<WatchExpression> FindExpression(uint32_t id) {
        for (auto& expr : m_expressions) {
            if (expr->id == id) return expr;
        }
        return nullptr;
    }

    std::shared_ptr<WatchExpression> HitTest(int x, int y) {
        int row = (y + m_scrollOffset) / m_config.rowHeight;
        if (row < 0 || row >= static_cast<int>(m_expressions.size())) {
            return nullptr;
        }
        return m_expressions[row];
    }

    void DrawExpression(HDC hdc, const std::shared_ptr<WatchExpression>& expr,
                        int row, const RECT& panelRect) {
        int y = row * m_config.rowHeight - m_scrollOffset;
        if (y + m_config.rowHeight < 0 || y > panelRect.bottom - panelRect.top) {
            return;  // Clip
        }

        int x = panelRect.left;
        int rowHeight = m_config.rowHeight;
        
        // Selection background
        if (expr == m_selectedExpression) {
            RECT selRect = {x, y, panelRect.right, y + rowHeight};
            FillRect(hdc, &selRect, CreateSolidBrush(m_config.selectedColor));
        }

        // Expression (or edit field)
        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, m_hFont);
        
        if (m_isEditing && expr == m_editingExpression) {
            // Draw edit box background
            RECT editRect = {x + 2, y + 1, x + m_config.expressionColumnWidth - 4, y + rowHeight - 1};
            FillRect(hdc, &editRect, CreateSolidBrush(RGB(50, 50, 50)));
            
            // Draw edit text
            SetTextColor(hdc, RGB(255, 255, 255));
            DrawTextW(hdc, m_editBuffer.c_str(), -1, &editRect,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            
            // Draw cursor
            if ((GetTickCount() / 500) % 2 == 0) {
                SIZE textSize;
                GetTextExtentPoint32W(hdc, m_editBuffer.c_str(), 
                                      static_cast<int>(m_editBuffer.length()), &textSize);
                MoveToEx(hdc, x + 4 + textSize.cx, y + 3, nullptr);
                LineTo(hdc, x + 4 + textSize.cx, y + rowHeight - 3);
            }
        } else {
            // Normal expression display
            SetTextColor(hdc, m_config.expressionColor);
            RECT exprRect = {x + 4, y, x + m_config.expressionColumnWidth, y + rowHeight};
            DrawTextW(hdc, expr->expression.c_str(), -1, &exprRect,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        }
        
        x += m_config.expressionColumnWidth;
        
        // Value with state-based coloring
        COLORREF valueColor = m_config.valueColor;
        switch (expr->state) {
            case WatchState::Error:
                valueColor = m_config.errorColor;
                break;
            case WatchState::Pending:
                valueColor = m_config.pendingColor;
                break;
            case WatchState::Stale:
                valueColor = RGB(180, 180, 180);  // Lighter gray
                break;
            default:
                break;
        }
        
        SetTextColor(hdc, valueColor);
        RECT valueRect = {x, y, x + m_config.valueColumnWidth, y + rowHeight};
        
        std::wstring displayValue = expr->value;
        if (expr->state == WatchState::Error) {
            displayValue = L"<" + expr->errorMessage + L">";
        } else if (expr->state == WatchState::Pending) {
            displayValue = L"...";
        }
        
        DrawTextW(hdc, displayValue.c_str(), -1, &valueRect,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        
        // Type
        if (m_config.showTypes && !expr->type.empty()) {
            x += m_config.valueColumnWidth;
            SetTextColor(hdc, m_config.typeColor);
            RECT typeRect = {x, y, x + m_config.typeColumnWidth, y + rowHeight};
            DrawTextW(hdc, expr->type.c_str(), -1, &typeRect,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        }
    }

    void SortExpressions() {
        std::sort(m_expressions.begin(), m_expressions.end(),
                  [](const auto& a, const auto& b) {
                      return a->sortOrder < b->sortOrder;
                  });
    }
};

// ============================================================================
// WatchExpressionsPanel Public API
// ============================================================================

WatchExpressionsPanel::WatchExpressionsPanel() : m_impl(std::make_unique<Impl>()) {}
WatchExpressionsPanel::~WatchExpressionsPanel() = default;

bool WatchExpressionsPanel::Initialize(HWND parentWindow) {
    m_impl->m_parent = parentWindow;
    m_impl->CreateFont();
    return true;
}

void WatchExpressionsPanel::Shutdown() {
    SaveToSettings();
    m_impl->m_expressions.clear();
}

void WatchExpressionsPanel::SetConfig(const WatchPanelConfig& config) {
    m_impl->m_config = config;
    m_impl->CreateFont();
}

uint32_t WatchExpressionsPanel::AddExpression(const std::wstring& expression) {
    auto expr = std::make_shared<WatchExpression>();
    expr->id = m_impl->m_nextId++;
    expr->expression = expression;
    expr->state = WatchState::Pending;
    expr->sortOrder = static_cast<int>(m_impl->m_expressions.size());
    expr->lastEvaluated = std::chrono::system_clock::now();
    
    m_impl->m_expressions.push_back(expr);
    
    if (m_impl->m_onAdd) {
        m_impl->m_onAdd(*expr);
    }
    
    if (m_impl->m_onEvaluate) {
        m_impl->m_onEvaluate(expression, expr->id);
    }
    
    Invalidate();
    return expr->id;
}

void WatchExpressionsPanel::RemoveExpression(uint32_t watchId) {
    auto it = std::remove_if(m_impl->m_expressions.begin(), m_impl->m_expressions.end(),
                             [watchId](const auto& e) { return e->id == watchId; });
    
    if (it != m_impl->m_expressions.end()) {
        if (m_impl->m_onRemove) {
            m_impl->m_onRemove(watchId);
        }
        m_impl->m_expressions.erase(it, m_impl->m_expressions.end());
        
        // Update sort orders
        for (size_t i = 0; i < m_impl->m_expressions.size(); ++i) {
            m_impl->m_expressions[i]->sortOrder = static_cast<int>(i);
        }
        
        Invalidate();
    }
}

void WatchExpressionsPanel::RemoveAllExpressions() {
    for (auto& expr : m_impl->m_expressions) {
        if (m_impl->m_onRemove) {
            m_impl->m_onRemove(expr->id);
        }
    }
    m_impl->m_expressions.clear();
    Invalidate();
}

void WatchExpressionsPanel::UpdateExpression(uint32_t watchId, const std::wstring& value,
                                              const std::wstring& type) {
    auto expr = m_impl->FindExpression(watchId);
    if (expr) {
        expr->value = value;
        expr->type = type;
        expr->state = WatchState::Valid;
        expr->lastEvaluated = std::chrono::system_clock::now();
        expr->evaluationCount++;
        Invalidate();
    }
}

void WatchExpressionsPanel::SetExpressionError(uint32_t watchId, const std::wstring& errorMessage) {
    auto expr = m_impl->FindExpression(watchId);
    if (expr) {
        expr->state = WatchState::Error;
        expr->errorMessage = errorMessage;
        expr->lastEvaluated = std::chrono::system_clock::now();
        Invalidate();
    }
}

void WatchExpressionsPanel::EvaluateAll() {
    if (!m_impl->m_onEvaluate) return;
    
    for (auto& expr : m_impl->m_expressions) {
        expr->state = WatchState::Pending;
        m_impl->m_onEvaluate(expr->expression, expr->id);
    }
    Invalidate();
}

void WatchExpressionsPanel::MarkAllStale() {
    for (auto& expr : m_impl->m_expressions) {
        if (expr->state == WatchState::Valid) {
            expr->state = WatchState::Stale;
        }
    }
    Invalidate();
}

void WatchExpressionsPanel::ClearValues() {
    for (auto& expr : m_impl->m_expressions) {
        expr->value.clear();
        expr->type.clear();
        expr->state = WatchState::Pending;
    }
    Invalidate();
}

void WatchExpressionsPanel::LoadFromSettings() {
    // Load from settings file
    std::wifstream file("watch_expressions.txt");
    if (!file.is_open()) return;
    
    std::wstring line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != L'#') {
            AddExpression(line);
        }
    }
}

void WatchExpressionsPanel::SaveToSettings() {
    // Save pinned expressions
    std::wofstream file("watch_expressions.txt");
    if (!file.is_open()) return;
    
    file << L"# RawrXD Watch Expressions\n";
    for (auto& expr : m_impl->m_expressions) {
        if (expr->isPinned) {
            file << expr->expression << L"\n";
        }
    }
}

std::vector<WatchExpression> WatchExpressionsPanel::GetExpressions() const {
    std::vector<WatchExpression> result;
    for (auto& expr : m_impl->m_expressions) {
        result.push_back(*expr);
    }
    return result;
}

std::shared_ptr<WatchExpression> WatchExpressionsPanel::GetExpression(uint32_t watchId) {
    return m_impl->FindExpression(watchId);
}

size_t WatchExpressionsPanel::GetExpressionCount() const {
    return m_impl->m_expressions.size();
}

void WatchExpressionsPanel::Render(HDC hdc, const RECT& panelRect) {
    // Background
    FillRect(hdc, &panelRect, CreateSolidBrush(m_impl->m_config.backgroundColor));
    
    // Draw all expressions
    for (size_t i = 0; i < m_impl->m_expressions.size(); ++i) {
        m_impl->DrawExpression(hdc, m_impl->m_expressions[i], 
                               static_cast<int>(i), panelRect);
    }
    
    // Draw "Add Expression..." hint if empty
    if (m_impl->m_expressions.empty()) {
        SetTextColor(hdc, RGB(128, 128, 128));
        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, m_impl->m_hFont);
        RECT hintRect = {panelRect.left + 10, panelRect.top + 10, 
                         panelRect.right - 10, panelRect.top + 30};
        DrawTextW(hdc, L"Click to add watch expression...", -1, &hintRect, DT_LEFT);
    }
}

void WatchExpressionsPanel::Invalidate() {
    if (m_impl->m_hwnd) {
        ::InvalidateRect(m_impl->m_hwnd, nullptr, FALSE);
    }
}

void WatchExpressionsPanel::SetExpressionSelectedCallback(ExpressionSelectedCallback callback) {
    m_impl->m_onSelect = callback;
}

void WatchExpressionsPanel::SetEvaluateExpressionCallback(EvaluateExpressionCallback callback) {
    m_impl->m_onEvaluate = callback;
}

void WatchExpressionsPanel::SetExpressionAddedCallback(ExpressionAddedCallback callback) {
    m_impl->m_onAdd = callback;
}

void WatchExpressionsPanel::SetExpressionRemovedCallback(ExpressionRemovedCallback callback) {
    m_impl->m_onRemove = callback;
}

bool WatchExpressionsPanel::OnMouseClick(int x, int y) {
    auto expr = m_impl->HitTest(x, y);
    if (expr) {
        m_impl->m_selectedExpression = expr;
        if (m_impl->m_onSelect) {
            m_impl->m_onSelect(*expr);
        }
        Invalidate();
        return true;
    }
    return false;
}

bool WatchExpressionsPanel::OnMouseDoubleClick(int x, int y) {
    auto expr = m_impl->HitTest(x, y);
    if (expr) {
        StartEdit(expr->id);
        return true;
    }
    return false;
}

bool WatchExpressionsPanel::OnKeyDown(WPARAM keyCode) {
    switch (keyCode) {
        case VK_DELETE:
            if (m_impl->m_selectedExpression) {
                RemoveExpression(m_impl->m_selectedExpression->id);
            }
            return true;
            
        case VK_F2:
            if (m_impl->m_selectedExpression) {
                StartEdit(m_impl->m_selectedExpression->id);
            }
            return true;
            
        case VK_RETURN:
            if (m_impl->m_isEditing) {
                CommitEdit(m_impl->m_editBuffer);
            } else if (m_impl->m_selectedExpression) {
                // Re-evaluate selected
                if (m_impl->m_onEvaluate) {
                    m_impl->m_onEvaluate(m_impl->m_selectedExpression->expression,
                                          m_impl->m_selectedExpression->id);
                }
            }
            return true;
            
        case VK_ESCAPE:
            if (m_impl->m_isEditing) {
                CancelEdit();
                return true;
            }
            break;
    }
    return false;
}

bool WatchExpressionsPanel::OnChar(wchar_t ch) {
    if (!m_impl->m_isEditing) return false;
    
    if (ch == VK_RETURN) {
        CommitEdit(m_impl->m_editBuffer);
        return true;
    } else if (ch == VK_ESCAPE) {
        CancelEdit();
        return true;
    } else if (ch == VK_BACK) {
        if (!m_impl->m_editBuffer.empty()) {
            m_impl->m_editBuffer.pop_back();
            Invalidate();
        }
        return true;
    } else if (ch >= 32) {
        m_impl->m_editBuffer += ch;
        Invalidate();
        return true;
    }
    return false;
}

void WatchExpressionsPanel::StartEdit(uint32_t watchId) {
    auto expr = m_impl->FindExpression(watchId);
    if (!expr) return;
    
    m_impl->m_editingExpression = expr;
    m_impl->m_editBuffer = expr->expression;
    m_impl->m_isEditing = true;
    Invalidate();
}

void WatchExpressionsPanel::CommitEdit(const std::wstring& newExpression) {
    if (!m_impl->m_isEditing || !m_impl->m_editingExpression) return;
    
    // Remove old and add new (to trigger re-evaluation)
    uint32_t oldId = m_impl->m_editingExpression->id;
    RemoveExpression(oldId);
    AddExpression(newExpression);
    
    m_impl->m_isEditing = false;
    m_impl->m_editingExpression.reset();
    m_impl->m_editBuffer.clear();
    Invalidate();
}

void WatchExpressionsPanel::CancelEdit() {
    m_impl->m_isEditing = false;
    m_impl->m_editingExpression.reset();
    m_impl->m_editBuffer.clear();
    Invalidate();
}

bool WatchExpressionsPanel::IsEditing() const {
    return m_impl->m_isEditing;
}

void WatchExpressionsPanel::QuickAddFromVariable(const std::wstring& variableName) {
    AddExpression(variableName);
}

void WatchExpressionsPanel::QuickAddFromSelection(const std::wstring& selectedText) {
    AddExpression(selectedText);
}

void WatchExpressionsPanel::SetSize(int width, int height) {
    m_impl->m_width = width;
    m_impl->m_height = height;
}

SIZE WatchExpressionsPanel::GetPreferredSize() const {
    return {m_impl->m_width, m_impl->m_height};
}

// ============================================================================
// WatchExpressionsIntegration Implementation
// ============================================================================

class WatchExpressionsIntegration::Impl {
public:
    WatchExpressionsPanel* m_panel = nullptr;
    void* m_dapService = nullptr;
    bool m_initialized = false;
    bool m_autoEvaluate = true;
};

WatchExpressionsIntegration::WatchExpressionsIntegration() : m_impl(std::make_unique<Impl>()) {}
WatchExpressionsIntegration::~WatchExpressionsIntegration() = default;

bool WatchExpressionsIntegration::Initialize(WatchExpressionsPanel* panel, void* dapService) {
    m_impl->m_panel = panel;
    m_impl->m_dapService = dapService;
    m_impl->m_initialized = true;
    
    // Set up callbacks
    panel->SetEvaluateExpressionCallback([this](const std::wstring& expr, uint32_t id) {
        // This would call DapService::EvaluateExpression
        // For now, just a placeholder
    });
    
    // Load saved watches
    LoadWatches();
    
    return true;
}

void WatchExpressionsIntegration::Shutdown() {
    SaveWatches();
    m_impl->m_initialized = false;
}

void WatchExpressionsIntegration::OnExecutionStopped(uint32_t threadId, uint32_t frameId) {
    if (!m_impl->m_initialized || !m_impl->m_autoEvaluate) return;
    
    m_impl->m_panel->EvaluateAll();
}

void WatchExpressionsIntegration::OnExecutionResumed() {
    if (!m_impl->m_initialized) return;
    
    m_impl->m_panel->MarkAllStale();
}

void WatchExpressionsIntegration::OnEvaluationComplete(uint32_t watchId, 
                                                       const std::wstring& value,
                                                       const std::wstring& type) {
    if (!m_impl->m_initialized) return;
    
    m_impl->m_panel->UpdateExpression(watchId, value, type);
}

void WatchExpressionsIntegration::OnEvaluationError(uint32_t watchId, 
                                                      const std::wstring& error) {
    if (!m_impl->m_initialized) return;
    
    m_impl->m_panel->SetExpressionError(watchId, error);
}

void WatchExpressionsIntegration::LoadWatches() {
    if (!m_impl->m_initialized) return;
    
    m_impl->m_panel->LoadFromSettings();
}

void WatchExpressionsIntegration::SaveWatches() {
    if (!m_impl->m_initialized) return;
    
    m_impl->m_panel->SaveToSettings();
}

} // namespace UI
} // namespace RawrXD
