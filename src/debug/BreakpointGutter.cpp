// BreakpointGutter.cpp
// Phase 24B: Visual Breakpoint Management - Implementation
// ============================================================================

#include "BreakpointGutter.hpp"
#include "DapService.hpp"
#include <windowsx.h>
#include <gdiplus.h>
#include <fstream>
#include <json.hpp>

#pragma comment(lib, "gdiplus.lib")

namespace RawrXD {
namespace Debug {
namespace UI {

using json = nlohmann::json;

// ============================================================================
// BreakpointGutter Implementation
// ============================================================================
BreakpointGutter::BreakpointGutter() = default;
BreakpointGutter::~BreakpointGutter() = default;

bool BreakpointGutter::Create(HWND hwndParent, int width) {
    hwndParent_ = hwndParent;
    width_ = width;
    
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"RawrXD_BreakpointGutter";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    
    RegisterClassExW(&wc);
    
    hwnd_ = CreateWindowExW(WS_EX_STATICEDGE, L"RawrXD_BreakpointGutter", L"",
                           WS_VISIBLE | WS_CHILD,
                           0, 0, width, 100,
                           hwndParent, nullptr, GetModuleHandle(nullptr), this);
    
    return hwnd_ != nullptr;
}

void BreakpointGutter::Destroy() {
    if (hwnd_) {
        DestroyWindow(hwnd_);
        hwnd_ = nullptr;
    }
}

void BreakpointGutter::SetPosition(int x, int y, int height) {
    x_ = x;
    y_ = y;
    height_ = height;
    
    if (hwnd_) {
        SetWindowPos(hwnd_, nullptr, x, y, width_, height, SWP_NOZORDER);
    }
}

void BreakpointGutter::SetLineHeight(int lineHeight) {
    lineHeight_ = lineHeight;
    Invalidate();
}

void BreakpointGutter::SetScrollOffset(int scrollOffset) {
    scrollOffset_ = scrollOffset;
    Invalidate();
}

// ============================================================================
// Breakpoint Management
// ============================================================================
void BreakpointGutter::ToggleBreakpoint(uint32_t line) {
    auto it = breakpoints_.find(line);
    if (it != breakpoints_.end()) {
        // Remove existing breakpoint
        breakpoints_.erase(it);
        if (onBreakpointToggled) {
            onBreakpointToggled(line, false);
        }
    } else {
        // Add new breakpoint
        BreakpointInfo bp;
        bp.id = nextBreakpointId_++;
        bp.line = line;
        bp.enabled = true;
        bp.verified = false;  // Will be verified by debugger
        breakpoints_[line] = bp;
        
        if (onBreakpointToggled) {
            onBreakpointToggled(line, true);
        }
    }
    
    Invalidate();
}

void BreakpointGutter::AddBreakpoint(const BreakpointInfo& bp) {
    breakpoints_[bp.line] = bp;
    if (bp.id >= nextBreakpointId_) {
        nextBreakpointId_ = bp.id + 1;
    }
    Invalidate();
}

void BreakpointGutter::RemoveBreakpoint(uint32_t line) {
    breakpoints_.erase(line);
    Invalidate();
}

void BreakpointGutter::RemoveBreakpointById(uint32_t breakpointId) {
    for (auto it = breakpoints_.begin(); it != breakpoints_.end(); ++it) {
        if (it->second.id == breakpointId) {
            breakpoints_.erase(it);
            Invalidate();
            return;
        }
    }
}

void BreakpointGutter::UpdateBreakpoint(const BreakpointInfo& bp) {
    for (auto& [line, existing] : breakpoints_) {
        if (existing.id == bp.id) {
            existing = bp;
            Invalidate();
            return;
        }
    }
}

void BreakpointGutter::ClearAllBreakpoints() {
    breakpoints_.clear();
    Invalidate();
}

bool BreakpointGutter::HasBreakpoint(uint32_t line) const {
    return breakpoints_.find(line) != breakpoints_.end();
}

BreakpointInfo BreakpointGutter::GetBreakpoint(uint32_t line) const {
    auto it = breakpoints_.find(line);
    if (it != breakpoints_.end()) {
        return it->second;
    }
    return BreakpointInfo{};
}

std::vector<BreakpointInfo> BreakpointGutter::GetAllBreakpoints() const {
    std::vector<BreakpointInfo> result;
    for (const auto& [line, bp] : breakpoints_) {
        result.push_back(bp);
    }
    return result;
}

// ============================================================================
// Visual State
// ============================================================================
void BreakpointGutter::SetCurrentLine(uint32_t line) {
    currentLine_ = line;
    Invalidate();
}

void BreakpointGutter::ClearCurrentLine() {
    currentLine_ = 0;
    Invalidate();
}

void BreakpointGutter::SetHoveredLine(uint32_t line) {
    if (hoveredLine_ != line) {
        hoveredLine_ = line;
        Invalidate();
    }
}

void BreakpointGutter::ClearHoveredLine() {
    if (hoveredLine_ != 0) {
        hoveredLine_ = 0;
        Invalidate();
    }
}

// ============================================================================
// Rendering
// ============================================================================
void BreakpointGutter::Invalidate() {
    if (hwnd_) {
        InvalidateRect(hwnd_, nullptr, FALSE);
    }
}

void BreakpointGutter::Render(HDC hdc) {
    RECT rc;
    GetClientRect(hwnd_, &rc);
    
    // Fill background
    FillRect(hdc, &rc, (HBRUSH)(COLOR_WINDOW + 1));
    
    // Draw border
    HPEN hPen = CreatePen(PS_SOLID, 1, RGB(200, 200, 200));
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
    MoveToEx(hdc, rc.right - 1, 0, nullptr);
    LineTo(hdc, rc.right - 1, rc.bottom);
    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);
    
    // Calculate visible lines
    int firstVisibleLine = scrollOffset_ / lineHeight_ + 1;
    int lastVisibleLine = firstVisibleLine + (height_ / lineHeight_) + 1;
    
    // Draw breakpoints
    for (const auto& [line, bp] : breakpoints_) {
        if (line >= firstVisibleLine && line <= lastVisibleLine) {
            DrawBreakpoint(hdc, YFromLine(line), bp);
        }
    }
    
    // Draw current line indicator
    if (currentLine_ >= firstVisibleLine && currentLine_ <= lastVisibleLine) {
        DrawCurrentLineIndicator(hdc, YFromLine(currentLine_));
    }
    
    // Draw hover indicator
    if (hoveredLine_ >= firstVisibleLine && hoveredLine_ <= lastVisibleLine) {
        DrawHoverIndicator(hdc, YFromLine(hoveredLine_));
    }
}

void BreakpointGutter::DrawBreakpoint(HDC hdc, int y, const BreakpointInfo& bp) {
    int centerX = width_ / 2;
    int centerY = y + lineHeight_ / 2;
    
    // Choose color based on state
    COLORREF color;
    if (!bp.enabled) {
        color = RGB(150, 150, 150);  // Gray for disabled
    } else if (!bp.verified) {
        color = RGB(255, 165, 0);    // Orange for unverified
    } else {
        color = RGB(220, 20, 60);    // Red for active
    }
    
    // Draw circle
    HBRUSH hBrush = CreateSolidBrush(color);
    HPEN hPen = CreatePen(PS_SOLID, 1, color);
    HGDIOBJ hOldBrush = SelectObject(hdc, hBrush);
    HGDIOBJ hOldPen = SelectObject(hdc, hPen);
    
    Ellipse(hdc, centerX - DOT_SIZE/2, centerY - DOT_SIZE/2,
            centerX + DOT_SIZE/2, centerY + DOT_SIZE/2);
    
    SelectObject(hdc, hOldBrush);
    SelectObject(hdc, hOldPen);
    DeleteObject(hBrush);
    DeleteObject(hPen);
    
    // Draw condition indicator (small dot)
    if (!bp.condition.empty()) {
        HBRUSH hCondBrush = CreateSolidBrush(RGB(255, 255, 255));
        SelectObject(hdc, hCondBrush);
        Ellipse(hdc, centerX - 3, centerY - 3, centerX + 3, centerY + 3);
        SelectObject(hdc, hOldBrush);
        DeleteObject(hCondBrush);
    }
}

void BreakpointGutter::DrawCurrentLineIndicator(HDC hdc, int y) {
    int centerX = width_ / 2;
    int centerY = y + lineHeight_ / 2;
    
    // Draw yellow arrow
    POINT points[3] = {
        {centerX - 6, centerY - 6},
        {centerX + 6, centerY},
        {centerX - 6, centerY + 6}
    };
    
    HBRUSH hBrush = CreateSolidBrush(RGB(255, 215, 0));  // Gold
    HPEN hPen = CreatePen(PS_SOLID, 1, RGB(200, 170, 0));
    
    HGDIOBJ hOldBrush = SelectObject(hdc, hBrush);
    HGDIOBJ hOldPen = SelectObject(hdc, hPen);
    
    Polygon(hdc, points, 3);
    
    SelectObject(hdc, hOldBrush);
    SelectObject(hdc, hOldPen);
    DeleteObject(hBrush);
    DeleteObject(hPen);
}

void BreakpointGutter::DrawHoverIndicator(HDC hdc, int y) {
    RECT rc;
    rc.left = 2;
    rc.right = width_ - 2;
    rc.top = y + 2;
    rc.bottom = y + lineHeight_ - 2;
    
    // Light gray highlight
    HBRUSH hBrush = CreateSolidBrush(RGB(230, 230, 230));
    FillRect(hdc, &rc, hBrush);
    DeleteObject(hBrush);
}

// ============================================================================
// Coordinate Conversion
// ============================================================================
uint32_t BreakpointGutter::LineFromY(int y) const {
    return (y + scrollOffset_) / lineHeight_ + 1;
}

int BreakpointGutter::YFromLine(uint32_t line) const {
    return (line - 1) * lineHeight_ - scrollOffset_;
}

// ============================================================================
// Event Handling
// ============================================================================
void BreakpointGutter::OnMouseMove(int x, int y) {
    uint32_t line = LineFromY(y);
    SetHoveredLine(line);
}

void BreakpointGutter::OnMouseLeave() {
    ClearHoveredLine();
}

bool BreakpointGutter::OnMouseClick(int x, int y) {
    uint32_t line = LineFromY(y);
    if (line > 0) {
        ToggleBreakpoint(line);
        return true;
    }
    return false;
}

void BreakpointGutter::OnContextMenu(int x, int y) {
    uint32_t line = LineFromY(y);
    auto bp = GetBreakpoint(line);
    
    HMENU hMenu = CreatePopupMenu();
    
    if (bp.id != 0) {
        // Breakpoint exists - show options
        AppendMenuW(hMenu, MF_STRING, 1, L"Remove Breakpoint");
        AppendMenuW(hMenu, MF_STRING | (bp.enabled ? MF_CHECKED : 0), 2, L"Enabled");
        AppendMenuW(hMenu, MF_STRING, 3, L"Edit Condition...");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenu, MF_STRING, 4, L"Go to Breakpoint");
    } else {
        // No breakpoint - show add option
        AppendMenuW(hMenu, MF_STRING, 1, L"Add Breakpoint");
    }
    
    AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hMenu, MF_STRING, 5, L"Remove All Breakpoints");
    
    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_LEFTALIGN,
                            x, y, 0, hwnd_, nullptr);
    DestroyMenu(hMenu);
    
    switch (cmd) {
        case 1:
            if (bp.id != 0) {
                RemoveBreakpoint(line);
            } else {
                ToggleBreakpoint(line);
            }
            break;
        case 2:
            // Toggle enabled
            if (onBreakpointEnabledChanged) {
                onBreakpointEnabledChanged(line);
            }
            break;
        case 3:
            if (onBreakpointConditionEdit) {
                onBreakpointConditionEdit(line);
            }
            break;
        case 4:
            if (onGoToBreakpoint) {
                onGoToBreakpoint(line);
            }
            break;
        case 5:
            ClearAllBreakpoints();
            break;
    }
}

// ============================================================================
// Debugger Sync
// ============================================================================
void BreakpointGutter::SyncWithDebugger(DapService* service) {
    if (!service) return;
    
    // Send all breakpoints to debugger
    for (const auto& [line, bp] : breakpoints_) {
        service->setBreakpoint(bp.filePath, bp.line, bp.condition);
    }
}

void BreakpointGutter::OnDebuggerBreakpointVerified(uint32_t breakpointId, bool verified) {
    for (auto& [line, bp] : breakpoints_) {
        if (bp.id == breakpointId) {
            bp.verified = verified;
            Invalidate();
            break;
        }
    }
}

void BreakpointGutter::OnDebuggerBreakpointHit(uint32_t line) {
    SetCurrentLine(line);
}

// ============================================================================
// Window Procedure
// ============================================================================
LRESULT CALLBACK BreakpointGutter::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    BreakpointGutter* gutter = nullptr;
    
    if (msg == WM_NCCREATE) {
        LPCREATESTRUCT lpcs = reinterpret_cast<LPCREATESTRUCT>(lParam);
        gutter = reinterpret_cast<BreakpointGutter*>(lpcs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(gutter));
    } else {
        gutter = reinterpret_cast<BreakpointGutter*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (!gutter) return DefWindowProc(hwnd, msg, wParam, lParam);
    
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            gutter->Render(hdc);
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_MOUSEMOVE: {
            gutter->OnMouseMove(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            return 0;
        }
        
        case WM_MOUSELEAVE: {
            gutter->OnMouseLeave();
            return 0;
        }
        
        case WM_LBUTTONDOWN: {
            if (gutter->OnMouseClick(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam))) {
                return 0;
            }
            break;
        }
        
        case WM_RBUTTONDOWN: {
            gutter->OnContextMenu(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            return 0;
        }
        
        case WM_SIZE: {
            gutter->height_ = HIWORD(lParam);
            return 0;
        }
        
        case WM_DESTROY: {
            return 0;
        }
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ============================================================================
// BreakpointManager Implementation
// ============================================================================
BreakpointManager& BreakpointManager::instance() {
    static BreakpointManager instance;
    return instance;
}

void BreakpointManager::SetBreakpointsForFile(const std::string& filePath,
                                                const std::vector<BreakpointInfo>& breakpoints) {
    std::lock_guard<std::mutex> lock(mutex_);
    fileBreakpoints_[filePath] = breakpoints;
}

std::vector<BreakpointInfo> BreakpointManager::GetBreakpointsForFile(const std::string& filePath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = fileBreakpoints_.find(filePath);
    if (it != fileBreakpoints_.end()) {
        return it->second;
    }
    return {};
}

void BreakpointManager::ClearAllBreakpoints() {
    std::lock_guard<std::mutex> lock(mutex_);
    fileBreakpoints_.clear();
}

void BreakpointManager::DisableAllBreakpoints() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [file, bps] : fileBreakpoints_) {
        for (auto& bp : bps) {
            bp.enabled = false;
        }
    }
}

void BreakpointManager::EnableAllBreakpoints() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [file, bps] : fileBreakpoints_) {
        for (auto& bp : bps) {
            bp.enabled = true;
        }
    }
}

bool BreakpointManager::SaveBreakpoints(const std::string& projectPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    json j;
    for (const auto& [file, bps] : fileBreakpoints_) {
        json fileBreakpoints = json::array();
        for (const auto& bp : bps) {
            json bpJson;
            bpJson["id"] = bp.id;
            bpJson["line"] = bp.line;
            bpJson["verified"] = bp.verified;
            bpJson["enabled"] = bp.enabled;
            bpJson["condition"] = bp.condition;
            fileBreakpoints.push_back(bpJson);
        }
        j[file] = fileBreakpoints;
    }
    
    std::ofstream file(projectPath + "/.rawrxd/breakpoints.json");
    if (!file) return false;
    file << j.dump(2);
    return true;
}

bool BreakpointManager::LoadBreakpoints(const std::string& projectPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ifstream file(projectPath + "/.rawrxd/breakpoints.json");
    if (!file) return false;
    
    json j;
    file >> j;
    
    fileBreakpoints_.clear();
    for (auto& [filePath, bpsJson] : j.items()) {
        std::vector<BreakpointInfo> bps;
        for (const auto& bpJson : bpsJson) {
            BreakpointInfo bp;
            bp.id = bpJson.value("id", 0);
            bp.filePath = filePath;
            bp.line = bpJson.value("line", 0);
            bp.verified = bpJson.value("verified", false);
            bp.enabled = bpJson.value("enabled", true);
            bp.condition = bpJson.value("condition", "");
            bps.push_back(bp);
        }
        fileBreakpoints_[filePath] = bps;
    }
    
    return true;
}

void BreakpointManager::SyncToDebugger(DapService* service) {
    if (!service) return;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [file, bps] : fileBreakpoints_) {
        for (const auto& bp : bps) {
            if (bp.enabled) {
                service->setBreakpoint(file, bp.line, bp.condition);
            }
        }
    }
}

void BreakpointManager::SyncFromDebugger(const std::vector<BreakpointInfo>& debuggerBreakpoints) {
    // Update local state based on debugger confirmation
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& dbBp : debuggerBreakpoints) {
        auto it = fileBreakpoints_.find(dbBp.filePath);
        if (it != fileBreakpoints_.end()) {
            for (auto& localBp : it->second) {
                if (localBp.line == dbBp.line) {
                    localBp.verified = dbBp.verified;
                    localBp.id = dbBp.id;
                }
            }
        }
    }
}

} // namespace UI
} // namespace Debug
} // namespace RawrXD
