// ============================================================================
// Phase 26: Variables Panel Implementation
// ============================================================================

#include "VariablesPanel.hpp"
#include "../debug/DapService.hpp"
#include <windowsx.h>
#include <algorithm>
#include <sstream>

namespace RawrXD {
namespace UI {

// ============================================================================
// Helper Functions
// ============================================================================

static COLORREF GetTypeColor(const VariablesPanelConfig& config, const std::wstring& type) {
    if (type.find(L"string") != std::wstring::npos || type.find(L"char") != std::wstring::npos) {
        return config.stringColor;
    }
    if (type.find(L"int") != std::wstring::npos || type.find(L"float") != std::wstring::npos || 
        type.find(L"double") != std::wstring::npos || type.find(L"number") != std::wstring::npos) {
        return config.numberColor;
    }
    if (type.find(L"bool") != std::wstring::npos) {
        return config.boolColor;
    }
    if (type.find(L"null") != std::wstring::npos || type.find(L"void") != std::wstring::npos) {
        return config.nullColor;
    }
    return config.typeColor;
}

static std::wstring VariableTypeToString(VariableType type) {
    switch (type) {
        case VariableType::Local: return L"Locals";
        case VariableType::Argument: return L"Arguments";
        case VariableType::Global: return L"Globals";
        case VariableType::Register: return L"Registers";
        case VariableType::Static: return L"Statics";
        default: return L"Unknown";
    }
}

// ============================================================================
// VariablesPanel::Impl
// ============================================================================

class VariablesPanel::Impl {
public:
    HWND m_hwnd = nullptr;
    HWND m_parent = nullptr;
    VariablesPanelConfig m_config;
    
    // Tree data
    std::vector<std::shared_ptr<VariableDisplayNode>> m_rootNodes;
    std::shared_ptr<VariableDisplayNode> m_selectedNode;
    std::shared_ptr<VariableDisplayNode> m_hoverNode;
    
    // Layout
    int m_width = 400;
    int m_height = 300;
    int m_scrollOffset = 0;
    int m_totalRows = 0;
    
    // Callbacks
    VariableSelectedCallback m_onSelect;
    ExpandVariableCallback m_onExpand;
    
    // State
    uint32_t m_currentFrameId = 0;
    std::wstring m_filter;
    HFONT m_hFont = nullptr;
    bool m_needsLayout = true;
    
    // Change tracking
    std::unordered_map<std::wstring, std::wstring> m_previousValues;
    uint64_t m_currentTick = 0;

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

    void LayoutNodes() {
        m_totalRows = 0;
        for (auto& root : m_rootNodes) {
            LayoutNodeRecursive(root, 0);
        }
        m_needsLayout = false;
    }

    void LayoutNodeRecursive(const std::shared_ptr<VariableDisplayNode>& node, int depth) {
        if (!node->isVisible) return;
        
        node->depth = depth;
        node->rowIndex = m_totalRows++;
        
        if (node->isExpanded) {
            for (auto& child : node->children) {
                child->isVisible = true;
                LayoutNodeRecursive(child, depth + 1);
            }
        } else {
            // Mark children as not visible
            for (auto& child : node->children) {
                child->isVisible = false;
                HideChildrenRecursive(child);
            }
        }
    }

    void HideChildrenRecursive(const std::shared_ptr<VariableDisplayNode>& node) {
        for (auto& child : node->children) {
            child->isVisible = false;
            HideChildrenRecursive(child);
        }
    }

    std::shared_ptr<VariableDisplayNode> HitTest(int x, int y) {
        int row = (y + m_scrollOffset) / m_config.rowHeight;
        
        for (auto& root : m_rootNodes) {
            auto found = HitTestRecursive(root, row);
            if (found) return found;
        }
        return nullptr;
    }

    std::shared_ptr<VariableDisplayNode> HitTestRecursive(
        const std::shared_ptr<VariableDisplayNode>& node, int targetRow) {
        if (!node->isVisible) return nullptr;
        if (node->rowIndex == targetRow) return node;
        if (node->isExpanded) {
            for (auto& child : node->children) {
                auto found = HitTestRecursive(child, targetRow);
                if (found) return found;
            }
        }
        return nullptr;
    }

    bool IsExpandIconClicked(int x, const std::shared_ptr<VariableDisplayNode>& node) {
        int iconX = node->depth * m_config.indentWidth + 2;
        return node->isExpandable && x >= iconX && x <= iconX + m_config.iconWidth;
    }

    void DrawNode(HDC hdc, const std::shared_ptr<VariableDisplayNode>& node, 
                  const RECT& panelRect) {
        if (!node->isVisible) return;
        
        int y = node->rowIndex * m_config.rowHeight - m_scrollOffset;
        if (y + m_config.rowHeight < 0 || y > panelRect.bottom - panelRect.top) {
            return;  // Clip
        }

        int x = panelRect.left;
        int rowHeight = m_config.rowHeight;
        
        // Selection background
        if (node == m_selectedNode) {
            RECT selRect = {x, y, panelRect.right, y + rowHeight};
            FillRect(hdc, &selRect, CreateSolidBrush(m_config.selectedColor));
        }

        // Indentation
        x += node->depth * m_config.indentWidth;

        // Expand/collapse icon
        if (node->isExpandable) {
            int iconX = x + 2;
            int iconY = y + (rowHeight - 8) / 2;
            
            // Draw triangle
            HPEN pen = CreatePen(PS_SOLID, 1, m_config.textColor);
            HPEN oldPen = (HPEN)SelectObject(hdc, pen);
            
            if (node->isExpanded) {
                // Down triangle
                MoveToEx(hdc, iconX, iconY, nullptr);
                LineTo(hdc, iconX + 8, iconY);
                LineTo(hdc, iconX + 4, iconY + 6);
                LineTo(hdc, iconX, iconY);
            } else {
                // Right triangle
                MoveToEx(hdc, iconX, iconY, nullptr);
                LineTo(hdc, iconX, iconY + 8);
                LineTo(hdc, iconX + 6, iconY + 4);
                LineTo(hdc, iconX, iconY);
            }
            
            SelectObject(hdc, oldPen);
            DeleteObject(pen);
        }
        x += m_config.iconWidth + 4;

        // Variable name
        SetTextColor(hdc, node->isModified ? m_config.modifiedColor : m_config.nameColor);
        SetBkMode(hdc, TRANSPARENT);
        SelectObject(hdc, m_hFont);
        
        RECT nameRect = {x, y, x + m_config.nameColumnWidth, y + rowHeight};
        DrawTextW(hdc, node->name.c_str(), -1, &nameRect, 
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        
        // Type (if enabled)
        if (m_config.showTypes && !node->type.empty()) {
            x += m_config.nameColumnWidth;
            SetTextColor(hdc, GetTypeColor(m_config, node->type));
            RECT typeRect = {x, y, x + m_config.typeColumnWidth, y + rowHeight};
            DrawTextW(hdc, node->type.c_str(), -1, &typeRect,
                      DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        }

        // Value
        x += m_config.typeColumnWidth;
        SetTextColor(hdc, node->isModified ? m_config.modifiedColor : m_config.valueColor);
        RECT valueRect = {x, y, panelRect.right - 4, y + rowHeight};
        DrawTextW(hdc, node->value.c_str(), -1, &valueRect,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    }

    void FilterNodes() {
        if (m_filter.empty()) {
            for (auto& root : m_rootNodes) {
                SetNodeVisible(root, true);
            }
        } else {
            for (auto& root : m_rootNodes) {
                FilterNodeRecursive(root);
            }
        }
        m_needsLayout = true;
    }

    void SetNodeVisible(const std::shared_ptr<VariableDisplayNode>& node, bool visible) {
        node->isVisible = visible;
        node->isHighlighted = false;
        for (auto& child : node->children) {
            SetNodeVisible(child, visible && node->isExpanded);
        }
    }

    bool FilterNodeRecursive(const std::shared_ptr<VariableDisplayNode>& node) {
        bool matches = node->name.find(m_filter) != std::wstring::npos ||
                     node->value.find(m_filter) != std::wstring::npos ||
                     node->type.find(m_filter) != std::wstring::npos;
        
        bool childMatches = false;
        for (auto& child : node->children) {
            if (FilterNodeRecursive(child)) {
                childMatches = true;
            }
        }
        
        node->isVisible = matches || childMatches;
        node->isHighlighted = matches;
        
        // Expand if filter matches and has children
        if (matches && childMatches) {
            node->isExpanded = true;
        }
        
        return node->isVisible;
    }
};

// ============================================================================
// VariablesPanel Public API
// ============================================================================

VariablesPanel::VariablesPanel() : m_impl(std::make_unique<Impl>()) {}
VariablesPanel::~VariablesPanel() = default;

bool VariablesPanel::Initialize(HWND parentWindow) {
    m_impl->m_parent = parentWindow;
    m_impl->CreateFont();
    return true;
}

void VariablesPanel::Shutdown() {
    m_impl->m_rootNodes.clear();
    m_impl->m_selectedNode.reset();
}

void VariablesPanel::SetConfig(const VariablesPanelConfig& config) {
    m_impl->m_config = config;
    m_impl->CreateFont();
    m_impl->m_needsLayout = true;
}

void VariablesPanel::UpdateVariables(const std::vector<Debug::Variable>& variables, 
                                      VariableType type) {
    // Find or create category node
    std::wstring categoryName = VariableTypeToString(type);
    std::shared_ptr<VariableDisplayNode> categoryNode = nullptr;
    
    for (auto& root : m_impl->m_rootNodes) {
        if (root->name == categoryName) {
            categoryNode = root;
            break;
        }
    }
    
    if (!categoryNode) {
        categoryNode = std::make_shared<VariableDisplayNode>();
        categoryNode->name = categoryName;
        categoryNode->type = L"category";
        categoryNode->isExpandable = true;
        categoryNode->isExpanded = true;
        categoryNode->isVisible = true;
        m_impl->m_rootNodes.push_back(categoryNode);
    }
    
    // Clear existing children
    categoryNode->children.clear();
    
    // Add variables
    for (const auto& var : variables) {
        auto node = std::make_shared<VariableDisplayNode>();
        node->name = std::wstring(var.name.begin(), var.name.end());
        node->value = std::wstring(var.value.begin(), var.value.end());
        node->type = std::wstring(var.type.begin(), var.type.end());
        node->varType = type;
        node->variablesReference = var.variablesReference;
        node->isExpandable = var.isExpandable;
        node->isExpanded = false;
        node->isVisible = true;
        node->depth = 1;
        
        // Check if modified
        std::wstring key = categoryName + L":" + node->name;
        auto it = m_impl->m_previousValues.find(key);
        if (it != m_impl->m_previousValues.end() && it->second != node->value) {
            node->isModified = true;
            node->lastModifiedTick = m_impl->m_currentTick;
        }
        m_impl->m_previousValues[key] = node->value;
        
        categoryNode->children.push_back(node);
    }
    
    m_impl->m_needsLayout = true;
}

void VariablesPanel::ClearVariables() {
    m_impl->m_rootNodes.clear();
    m_impl->m_selectedNode.reset();
    m_impl->m_totalRows = 0;
    m_impl->m_needsLayout = true;
}

void VariablesPanel::SetCurrentFrame(uint32_t frameId) {
    m_impl->m_currentFrameId = frameId;
    // Variables will be refreshed via DAP
}

void VariablesPanel::ExpandNode(const std::shared_ptr<VariableDisplayNode>& node) {
    if (node && node->isExpandable && !node->isExpanded) {
        node->isExpanded = true;
        if (m_impl->m_onExpand && node->variablesReference != 0) {
            m_impl->m_onExpand(node->variablesReference);
        }
        m_impl->m_needsLayout = true;
    }
}

void VariablesPanel::CollapseNode(const std::shared_ptr<VariableDisplayNode>& node) {
    if (node && node->isExpanded) {
        node->isExpanded = false;
        m_impl->m_needsLayout = true;
    }
}

void VariablesPanel::ToggleNode(const std::shared_ptr<VariableDisplayNode>& node) {
    if (node) {
        if (node->isExpanded) {
            CollapseNode(node);
        } else {
            ExpandNode(node);
        }
    }
}

void VariablesPanel::ExpandAll() {
    std::function<void(const std::shared_ptr<VariableDisplayNode>&)> expandRecursive =
        [&](const std::shared_ptr<VariableDisplayNode>& n) {
            if (n->isExpandable) {
                n->isExpanded = true;
                for (auto& child : n->children) {
                    expandRecursive(child);
                }
            }
        };
    
    for (auto& root : m_impl->m_rootNodes) {
        expandRecursive(root);
    }
    m_impl->m_needsLayout = true;
}

void VariablesPanel::CollapseAll() {
    std::function<void(const std::shared_ptr<VariableDisplayNode>&)> collapseRecursive =
        [&collapseRecursive](const std::shared_ptr<VariableDisplayNode>& n) {
            n->isExpanded = false;
            for (auto& child : n->children) {
                collapseRecursive(child);
            }
        };
    
    for (auto& root : m_impl->m_rootNodes) {
        collapseRecursive(root);
        root->isExpanded = true;  // Keep categories expanded
    }
    m_impl->m_needsLayout = true;
}

void VariablesPanel::UpdateChildVariables(uint32_t parentReference,
                                           const std::vector<Debug::Variable>& children) {
    // Find parent node
    std::function<std::shared_ptr<VariableDisplayNode>(
        const std::shared_ptr<VariableDisplayNode>&)> findParent =
        [&](const std::shared_ptr<VariableDisplayNode>& node) 
            -> std::shared_ptr<VariableDisplayNode> {
            if (node->variablesReference == parentReference) {
                return node;
            }
            for (auto& child : node->children) {
                auto found = findParent(child);
                if (found) return found;
            }
            return nullptr;
        };
    
    std::shared_ptr<VariableDisplayNode> parent = nullptr;
    for (auto& root : m_impl->m_rootNodes) {
        parent = findParent(root);
        if (parent) break;
    }
    
    if (!parent) return;
    
    // Update children
    parent->children.clear();
    for (const auto& var : children) {
        auto node = std::make_shared<VariableDisplayNode>();
        node->name = std::wstring(var.name.begin(), var.name.end());
        node->value = std::wstring(var.value.begin(), var.value.end());
        node->type = std::wstring(var.type.begin(), var.type.end());
        node->variablesReference = var.variablesReference;
        node->isExpandable = var.isExpandable;
        node->isExpanded = false;
        node->isVisible = true;
        node->depth = parent->depth + 1;
        parent->children.push_back(node);
    }
    
    m_impl->m_needsLayout = true;
}

void VariablesPanel::Render(HDC hdc, const RECT& panelRect) {
    if (m_impl->m_needsLayout) {
        m_impl->LayoutNodes();
    }
    
    // Background
    FillRect(hdc, &panelRect, CreateSolidBrush(m_impl->m_config.backgroundColor));
    
    // Draw all visible nodes
    for (auto& root : m_impl->m_rootNodes) {
        m_impl->DrawNode(hdc, root, panelRect);
    }
}

void VariablesPanel::Invalidate() {
    if (m_impl->m_hwnd) {
        ::InvalidateRect(m_impl->m_hwnd, nullptr, FALSE);
    }
}

void VariablesPanel::SetVariableSelectedCallback(VariableSelectedCallback callback) {
    m_impl->m_onSelect = callback;
}

void VariablesPanel::SetExpandVariableCallback(ExpandVariableCallback callback) {
    m_impl->m_onExpand = callback;
}

bool VariablesPanel::OnMouseClick(int x, int y) {
    auto node = m_impl->HitTest(x, y);
    if (!node) return false;
    
    if (m_impl->IsExpandIconClicked(x, node)) {
        ToggleNode(node);
    } else {
        m_impl->m_selectedNode = node;
        if (m_impl->m_onSelect) {
            m_impl->m_onSelect(*node);
        }
    }
    
    Invalidate();
    return true;
}

bool VariablesPanel::OnMouseDoubleClick(int x, int y) {
    auto node = m_impl->HitTest(x, y);
    if (node && node->isExpandable) {
        ToggleNode(node);
        Invalidate();
        return true;
    }
    return false;
}

bool VariablesPanel::OnKeyDown(WPARAM keyCode) {
    switch (keyCode) {
        case VK_LEFT:
            if (m_impl->m_selectedNode) {
                CollapseNode(m_impl->m_selectedNode);
                Invalidate();
            }
            return true;
            
        case VK_RIGHT:
            if (m_impl->m_selectedNode) {
                ExpandNode(m_impl->m_selectedNode);
                Invalidate();
            }
            return true;
            
        case VK_UP:
            // Navigate up
            return true;
            
        case VK_DOWN:
            // Navigate down
            return true;
    }
    return false;
}

void VariablesPanel::SetFilter(const std::wstring& filter) {
    m_impl->m_filter = filter;
    m_impl->FilterNodes();
    Invalidate();
}

void VariablesPanel::ClearFilter() {
    m_impl->m_filter.clear();
    m_impl->FilterNodes();
    Invalidate();
}

void VariablesPanel::SetSize(int width, int height) {
    m_impl->m_width = width;
    m_impl->m_height = height;
}

SIZE VariablesPanel::GetPreferredSize() const {
    return {m_impl->m_width, m_impl->m_height};
}

void VariablesPanel::MarkAllUnmodified() {
    std::function<void(const std::shared_ptr<VariableDisplayNode>&)> clearModified =
        [&clearModified](const std::shared_ptr<VariableDisplayNode>& n) {
            n->isModified = false;
            for (auto& child : n->children) {
                clearModified(child);
            }
        };
    
    for (auto& root : m_impl->m_rootNodes) {
        clearModified(root);
    }
}

void VariablesPanel::TrackChanges() {
    m_impl->m_currentTick++;
    m_impl->m_previousValues.clear();
    
    // Save current values
    std::function<void(const std::shared_ptr<VariableDisplayNode>&, 
                       const std::wstring&)> saveValues =
        [&](const std::shared_ptr<VariableDisplayNode>& n, 
            const std::wstring& prefix) {
            std::wstring key = prefix + L":" + n->name;
            m_impl->m_previousValues[key] = n->value;
            for (auto& child : n->children) {
                saveValues(child, key);
            }
        };
    
    for (auto& root : m_impl->m_rootNodes) {
        saveValues(root, L"");
    }
}

// ============================================================================
// VariablesIntegration Implementation
// ============================================================================

class VariablesIntegration::Impl {
public:
    VariablesPanel* m_panel = nullptr;
    void* m_dapService = nullptr;  // DapService*
    uint32_t m_currentFrameId = 0;
    bool m_initialized = false;
};

VariablesIntegration::VariablesIntegration() : m_impl(std::make_unique<Impl>()) {}
VariablesIntegration::~VariablesIntegration() = default;

bool VariablesIntegration::Initialize(VariablesPanel* panel, void* dapService) {
    m_impl->m_panel = panel;
    m_impl->m_dapService = dapService;
    m_impl->m_initialized = true;
    
    // Set up callbacks
    panel->SetExpandVariableCallback([this](uint32_t ref) {
        // Request child variables from DAP
        // This would call DapService::RequestVariables
    });
    
    return true;
}

void VariablesIntegration::Shutdown() {
    m_impl->m_initialized = false;
    m_impl->m_panel = nullptr;
    m_impl->m_dapService = nullptr;
}

void VariablesIntegration::OnFrameSelected(uint32_t frameId) {
    if (!m_impl->m_initialized) return;
    
    m_impl->m_currentFrameId = frameId;
    m_impl->m_panel->SetCurrentFrame(frameId);
    m_impl->m_panel->TrackChanges();  // Mark current values for change detection
    
    // Request variables for this frame from DAP
    // DapService would send scopesRequest then variablesRequest
}

void VariablesIntegration::OnVariablesReceived(uint32_t frameId,
                                              const std::vector<Debug::Variable>& variables) {
    if (!m_impl->m_initialized || frameId != m_impl->m_currentFrameId) return;
    
    m_impl->m_panel->UpdateVariables(variables, VariableType::Local);
    m_impl->m_panel->Invalidate();
}

void VariablesIntegration::OnChildVariablesReceived(uint32_t parentReference,
                                                   const std::vector<Debug::Variable>& children) {
    if (!m_impl->m_initialized) return;
    
    m_impl->m_panel->UpdateChildVariables(parentReference, children);
    m_impl->m_panel->Invalidate();
}

void VariablesIntegration::OnExecutionResumed() {
    if (!m_impl->m_initialized) return;
    
    m_impl->m_panel->MarkAllUnmodified();
    // Optionally clear: m_impl->m_panel->ClearVariables();
}

} // namespace UI
} // namespace RawrXD
