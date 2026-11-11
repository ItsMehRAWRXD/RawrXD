//=============================================================================
// RawrXD Breakpoint Manager Panel Implementation
// Win32 ListView-based breakpoint management
//=============================================================================
#include "BreakpointManagerPanel.hpp"
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>
#include <algorithm>
#include <string>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD {
namespace Win32 {

//=============================================================================
// Constants
//=============================================================================

static constexpr wchar_t g_szClassName[] = L"RawrXD_BreakpointManagerPanel";
static constexpr int ID_LISTVIEW = 1001;

//=============================================================================
// Constructor / Destructor
//=============================================================================

BreakpointManagerPanel::BreakpointManagerPanel() = default;

BreakpointManagerPanel::~BreakpointManagerPanel() {
    Destroy();
}

//=============================================================================
// Window Creation
//=============================================================================

bool BreakpointManagerPanel::Create(HWND hwndParent, HINSTANCE hInstance, int x, int y, int width, int height) {
    if (m_hwnd) return true;
    
    m_hwndParent = hwndParent;
    m_hInstance = hInstance;
    
    // Register window class if not already registered
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = g_szClassName;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    if (!GetClassInfoExW(hInstance, g_szClassName, &wc)) {
        if (!RegisterClassExW(&wc)) {
            return false;
        }
    }
    
    // Create panel window
    m_hwnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        g_szClassName,
        L"Breakpoints",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, width, height,
        hwndParent,
        NULL,
        hInstance,
        this
    );
    
    if (!m_hwnd) {
        return false;
    }
    
    // Create ListView child
    m_hwndListView = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS | 
        LVS_SINGLESEL | WS_VSCROLL | WS_HSCROLL,
        0, 0, width, height,
        m_hwnd,
        (HMENU)ID_LISTVIEW,
        hInstance,
        NULL
    );
    
    if (!m_hwndListView) {
        Destroy();
        return false;
    }
    
    // Set extended styles
    ListView_SetExtendedListViewStyle(m_hwndListView, 
        LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
    
    // Setup columns
    LVCOLUMN lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    
    // Enabled column (checkbox)
    lvc.iSubItem = COL_ENABLED;
    lvc.pszText = (LPWSTR)L"";
    lvc.cx = 30;
    ListView_InsertColumn(m_hwndListView, COL_ENABLED, &lvc);
    
    // File column
    lvc.iSubItem = COL_FILE;
    lvc.pszText = (LPWSTR)L"File";
    lvc.cx = 200;
    ListView_InsertColumn(m_hwndListView, COL_FILE, &lvc);
    
    // Line column
    lvc.iSubItem = COL_LINE;
    lvc.pszText = (LPWSTR)L"Line";
    lvc.cx = 50;
    ListView_InsertColumn(m_hwndListView, COL_LINE, &lvc);
    
    // Condition column
    lvc.iSubItem = COL_CONDITION;
    lvc.pszText = (LPWSTR)L"Condition";
    lvc.cx = 150;
    ListView_InsertColumn(m_hwndListView, COL_CONDITION, &lvc);
    
    // Hit count column
    lvc.iSubItem = COL_HITCOUNT;
    lvc.pszText = (LPWSTR)L"Hits";
    lvc.cx = 50;
    ListView_InsertColumn(m_hwndListView, COL_HITCOUNT, &lvc);
    
    // Address column
    lvc.iSubItem = COL_ADDRESS;
    lvc.pszText = (LPWSTR)L"Address";
    lvc.cx = 100;
    ListView_InsertColumn(m_hwndListView, COL_ADDRESS, &lvc);
    
    return true;
}

void BreakpointManagerPanel::Destroy() {
    if (m_hwndListView) {
        DestroyWindow(m_hwndListView);
        m_hwndListView = NULL;
    }
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = NULL;
    }
    m_breakpoints.clear();
}

//=============================================================================
// Window Procedure
//=============================================================================

LRESULT CALLBACK BreakpointManagerPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    BreakpointManagerPanel* pThis = nullptr;
    
    if (msg == WM_CREATE) {
        LPCREATESTRUCT lpcs = reinterpret_cast<LPCREATESTRUCT>(lParam);
        pThis = static_cast<BreakpointManagerPanel*>(lpcs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
    } else {
        pThis = reinterpret_cast<BreakpointManagerPanel*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (pThis) {
        return pThis->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT BreakpointManagerPanel::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SIZE: {
            // Resize ListView to fill panel
            if (m_hwndListView) {
                int width = LOWORD(lParam);
                int height = HIWORD(lParam);
                SetWindowPos(m_hwndListView, NULL, 0, 0, width, height, SWP_NOZORDER);
            }
            return 0;
        }
        
        case WM_NOTIFY: {
            LPNMHDR pnmh = reinterpret_cast<LPNMHDR>(lParam);
            if (pnmh->hwndFrom != m_hwndListView) {
                break;
            }
            
            switch (pnmh->code) {
                case LVN_ITEMCHANGED:
                    OnItemChanged(reinterpret_cast<NMLISTVIEW*>(lParam));
                    break;
                    
                case NM_DBLCLK:
                    OnDoubleClick(reinterpret_cast<NMITEMACTIVATE*>(lParam));
                    break;
                    
                case NM_RCLICK:
                    OnRightClick(reinterpret_cast<NMITEMACTIVATE*>(lParam));
                    break;
                    
                case LVN_KEYDOWN:
                    OnKeyDown(reinterpret_cast<NMLVKEYDOWN*>(lParam));
                    break;
                    
                case LVN_COLUMNCLICK:
                    OnColumnClick(reinterpret_cast<NMLISTVIEW*>(lParam));
                    break;
            }
            return 0;
        }
        
        case WM_DESTROY:
            m_hwnd = NULL;
            m_hwndListView = NULL;
            return 0;
    }
    
    return DefWindowProc(m_hwnd, msg, wParam, lParam);
}

//=============================================================================
// Breakpoint Management
//=============================================================================

void BreakpointManagerPanel::AddBreakpoint(const BreakpointInfo& bp) {
    // Check if already exists
    int existingIndex = FindBreakpointIndex(bp.id);
    if (existingIndex >= 0) {
        UpdateBreakpoint(bp);
        return;
    }
    
    // Add to internal list
    m_breakpoints.push_back(bp);
    
    // Add to ListView
    AddListViewItem(bp);
}

void BreakpointManagerPanel::UpdateBreakpoint(const BreakpointInfo& bp) {
    int index = FindBreakpointIndex(bp.id);
    if (index < 0) {
        AddBreakpoint(bp);
        return;
    }
    
    // Update internal list
    m_breakpoints[index] = bp;
    
    // Update ListView
    UpdateListViewItem(index, bp);
}

void BreakpointManagerPanel::RemoveBreakpoint(int breakpointId) {
    int index = FindBreakpointIndex(breakpointId);
    if (index < 0) return;
    
    // Remove from ListView
    ListView_DeleteItem(m_hwndListView, index);
    
    // Remove from internal list
    m_breakpoints.erase(m_breakpoints.begin() + index);
}

void BreakpointManagerPanel::ClearAllBreakpoints() {
    ListView_DeleteAllItems(m_hwndListView);
    m_breakpoints.clear();
    
    if (m_callbacks) {
        m_callbacks->OnClearAllBreakpoints();
    }
}

void BreakpointManagerPanel::SetBreakpoints(const std::vector<BreakpointInfo>& breakpoints) {
    // Clear existing
    ListView_DeleteAllItems(m_hwndListView);
    m_breakpoints = breakpoints;
    
    // Add all
    for (const auto& bp : m_breakpoints) {
        AddListViewItem(bp);
    }
}

//=============================================================================
// ListView Helpers
//=============================================================================

int BreakpointManagerPanel::AddListViewItem(const BreakpointInfo& bp) {
    LVITEM lvi = {};
    lvi.mask = LVIF_TEXT | LVIF_PARAM;
    lvi.iItem = ListView_GetItemCount(m_hwndListView);
    lvi.lParam = bp.id;
    
    // First column (enabled status) - use persistent storage
    static std::wstring s_enabledText;
    s_enabledText = bp.enabled ? L"☑" : L"☐";
    lvi.pszText = const_cast<LPWSTR>(s_enabledText.c_str());
    int index = ListView_InsertItem(m_hwndListView, &lvi);
    
    if (index >= 0) {
        UpdateListViewItem(index, bp);
    }
    
    return index;
}

void BreakpointManagerPanel::UpdateListViewItem(int index, const BreakpointInfo& bp) {
    // Enabled
    std::wstring enabledText = bp.enabled ? L"☑" : L"☐";
    ListView_SetItemText(m_hwndListView, index, COL_ENABLED, const_cast<LPWSTR>(enabledText.c_str()));
    
    // File
    ListView_SetItemText(m_hwndListView, index, COL_FILE, const_cast<LPWSTR>(bp.fileName.c_str()));
    
    // Line
    wchar_t lineText[32];
    swprintf_s(lineText, L"%d", bp.line);
    ListView_SetItemText(m_hwndListView, index, COL_LINE, lineText);
    
    // Condition
    std::wstring conditionWide(bp.condition.begin(), bp.condition.end());
    ListView_SetItemText(m_hwndListView, index, COL_CONDITION, const_cast<LPWSTR>(conditionWide.c_str()));
    
    // Hit count
    wchar_t hitText[32];
    swprintf_s(hitText, L"%d", bp.hitCount);
    ListView_SetItemText(m_hwndListView, index, COL_HITCOUNT, hitText);
    
    // Address
    if (bp.address != 0) {
        wchar_t addrText[32];
        swprintf_s(addrText, L"0x%016llX", bp.address);
        ListView_SetItemText(m_hwndListView, index, COL_ADDRESS, addrText);
    } else {
        ListView_SetItemText(m_hwndListView, index, COL_ADDRESS, (LPWSTR)L"");
    }
    
    // Update lParam
    LVITEM lvi = {};
    lvi.mask = LVIF_PARAM;
    lvi.iItem = index;
    lvi.lParam = bp.id;
    ListView_SetItem(m_hwndListView, &lvi);
}

int BreakpointManagerPanel::FindBreakpointIndex(int breakpointId) const {
    for (size_t i = 0; i < m_breakpoints.size(); ++i) {
        if (m_breakpoints[i].id == breakpointId) {
            return (int)i;
        }
    }
    return -1;
}

//=============================================================================
// Event Handlers
//=============================================================================

void BreakpointManagerPanel::OnItemChanged(NMLISTVIEW* pnmv) {
    // Handle checkbox toggle
    if ((pnmv->uChanged & LVIF_STATE) && 
        (pnmv->uNewState & LVIS_STATEIMAGEMASK) != (pnmv->uOldState & LVIS_STATEIMAGEMASK)) {
        
        int index = pnmv->iItem;
        if (index >= 0 && index < (int)m_breakpoints.size()) {
            int bpId = m_breakpoints[index].id;
            bool newEnabled = (pnmv->uNewState & LVIS_STATEIMAGEMASK) == 0x2000; // Checked state
            
            if (m_callbacks) {
                m_callbacks->OnBreakpointToggled(bpId, newEnabled);
            }
        }
    }
}

void BreakpointManagerPanel::OnDoubleClick(NMITEMACTIVATE* pnmia) {
    int index = pnmia->iItem;
    if (index >= 0 && index < (int)m_breakpoints.size()) {
        const auto& bp = m_breakpoints[index];
        if (m_callbacks) {
            m_callbacks->OnBreakpointNavigate(bp.filePath, bp.line);
        }
    }
}

void BreakpointManagerPanel::OnRightClick(NMITEMACTIVATE* pnmia) {
    ShowContextMenu(pnmia->iItem, pnmia->ptAction);
}

void BreakpointManagerPanel::OnKeyDown(NMLVKEYDOWN* pnmkd) {
    if (pnmkd->wVKey == VK_DELETE) {
        int selected = ListView_GetNextItem(m_hwndListView, -1, LVNI_SELECTED);
        if (selected >= 0 && selected < (int)m_breakpoints.size()) {
            int bpId = m_breakpoints[selected].id;
            if (m_callbacks) {
                m_callbacks->OnBreakpointDeleted(bpId);
            }
        }
    }
}

void BreakpointManagerPanel::OnColumnClick(NMLISTVIEW* pnmv) {
    SortItems(pnmv->iSubItem);
}

//=============================================================================
// Context Menu
//=============================================================================

void BreakpointManagerPanel::ShowContextMenu(int itemIndex, POINT pt) {
    HMENU hMenu = CreatePopupMenu();
    
    if (itemIndex >= 0) {
        const auto& bp = m_breakpoints[itemIndex];
        
        // Enable/Disable
        AppendMenu(hMenu, MF_STRING, 1, bp.enabled ? L"&Disable" : L"&Enable");
        AppendMenu(hMenu, MF_STRING, 2, L"&Delete");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
        AppendMenu(hMenu, MF_STRING, 3, L"&Edit Condition...");
        AppendMenu(hMenu, MF_STRING, 4, L"&Go to Source");
        AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    }
    
    AppendMenu(hMenu, MF_STRING, 10, L"Enable &All");
    AppendMenu(hMenu, MF_STRING, 11, L"Disable A&ll");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, 12, L"&Delete All");
    
    // Show menu
    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN, pt.x, pt.y, 0, m_hwnd, NULL);
    DestroyMenu(hMenu);
    
    // Handle selection
    switch (cmd) {
        case 1: // Toggle enable
            if (itemIndex >= 0 && m_callbacks) {
                m_callbacks->OnBreakpointToggled(m_breakpoints[itemIndex].id, !m_breakpoints[itemIndex].enabled);
            }
            break;
            
        case 2: // Delete
            if (itemIndex >= 0 && m_callbacks) {
                m_callbacks->OnBreakpointDeleted(m_breakpoints[itemIndex].id);
            }
            break;
            
        case 3: // Edit condition
            if (itemIndex >= 0) {
                BreakpointInfo bp = m_breakpoints[itemIndex];
                if (BreakpointPropertiesDialog::Show(m_hwnd, bp) && m_callbacks) {
                    m_callbacks->OnBreakpointConditionChanged(bp.id, bp.condition);
                }
            }
            break;
            
        case 4: // Go to source
            if (itemIndex >= 0 && m_callbacks) {
                m_callbacks->OnBreakpointNavigate(m_breakpoints[itemIndex].filePath, m_breakpoints[itemIndex].line);
            }
            break;
            
        case 10: // Enable all
            EnableAll();
            break;
            
        case 11: // Disable all
            DisableAll();
            break;
            
        case 12: // Delete all
            ClearAllBreakpoints();
            break;
    }
}

//=============================================================================
// Operations
//=============================================================================

void BreakpointManagerPanel::ToggleBreakpointEnabled(int breakpointId) {
    int index = FindBreakpointIndex(breakpointId);
    if (index >= 0) {
        m_breakpoints[index].enabled = !m_breakpoints[index].enabled;
        UpdateListViewItem(index, m_breakpoints[index]);
        
        if (m_callbacks) {
            m_callbacks->OnBreakpointToggled(breakpointId, m_breakpoints[index].enabled);
        }
    }
}

void BreakpointManagerPanel::SetBreakpointEnabled(int breakpointId, bool enabled) {
    int index = FindBreakpointIndex(breakpointId);
    if (index >= 0) {
        m_breakpoints[index].enabled = enabled;
        UpdateListViewItem(index, m_breakpoints[index]);
    }
}

void BreakpointManagerPanel::EnableAll() {
    for (auto& bp : m_breakpoints) {
        bp.enabled = true;
    }
    Refresh();
}

void BreakpointManagerPanel::DisableAll() {
    for (auto& bp : m_breakpoints) {
        bp.enabled = false;
    }
    Refresh();
}

void BreakpointManagerPanel::Refresh() {
    ListView_DeleteAllItems(m_hwndListView);
    for (const auto& bp : m_breakpoints) {
        AddListViewItem(bp);
    }
}

void BreakpointManagerPanel::UpdateHitCount(int breakpointId, int hitCount) {
    int index = FindBreakpointIndex(breakpointId);
    if (index >= 0) {
        m_breakpoints[index].hitCount = hitCount;
        UpdateListViewItem(index, m_breakpoints[index]);
    }
}

//=============================================================================
// Sorting
//=============================================================================

void BreakpointManagerPanel::SortItems(int column) {
    if (m_sortColumn == column) {
        m_sortAscending = !m_sortAscending;
    } else {
        m_sortColumn = column;
        m_sortAscending = true;
    }
    
    // Sort internal list
    std::sort(m_breakpoints.begin(), m_breakpoints.end(),
        [this, column](const BreakpointInfo& a, const BreakpointInfo& b) {
            bool result = false;
            switch (column) {
                case COL_FILE:
                    result = a.fileName < b.fileName;
                    break;
                case COL_LINE:
                    result = a.line < b.line;
                    break;
                case COL_CONDITION:
                    result = a.condition < b.condition;
                    break;
                case COL_HITCOUNT:
                    result = a.hitCount < b.hitCount;
                    break;
                case COL_ADDRESS:
                    result = a.address < b.address;
                    break;
                default:
                    result = a.id < b.id;
            }
            return m_sortAscending ? result : !result;
        });
    
    // Refresh ListView
    Refresh();
}

//=============================================================================
// Factory
//=============================================================================

BreakpointManagerPanel* BreakpointManagerFactory::s_panel = nullptr;

BreakpointManagerPanel* BreakpointManagerFactory::GetPanel() {
    if (!s_panel) {
        s_panel = new BreakpointManagerPanel();
    }
    return s_panel;
}

void BreakpointManagerFactory::DestroyPanel() {
    delete s_panel;
    s_panel = nullptr;
}

} // namespace Win32
} // namespace RawrXD
