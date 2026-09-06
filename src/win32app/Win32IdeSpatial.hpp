// ============================================================================
// Win32IdeSpatial.hpp — UI spatial manifest + layout arbiter
//
// Control A owns rectangle A. Control B owns rectangle B.
// Neither may silently write into the other's spatial allocation.
//
// PHASE: CaptureClient → Resolve → Clamp → Collapse → Validate → Apply
// SIZE_MINIMIZED / zero-client layout = FORBIDDEN
// ============================================================================
#pragma once

#include <algorithm>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>

namespace RawrXD {
namespace Ui {

enum class UiRegionId : uint16_t {
    Client = 0,
    Menu,
    MainToolbar,
    ActivityBar,
    LeftSidebar,
    AiChat,
    FileTree,
    EditorTabs,
    Breadcrumbs,
    EditorGutter,
    Editor,
    Minimap,
    RightSidebar,
    AgentPanel,
    Terminal,
    TerminalToolbar,
    TerminalOutput,
    TerminalInput,
    StatusBar,
    CommandHost,
    CommandLeftRail,
    TopContextBar,
    CommandConversation,
    ActivityStrip,
    CommandComposer,
    CommandFooter,
    Workspace,
    Count
};

enum class UiDock : uint8_t {
    Top = 0,
    Bottom,
    Left,
    Right,
    Fill,
    Floating
};

struct UiRegionManifest {
    UiRegionId id = UiRegionId::Client;
    UiRegionId parent = UiRegionId::Client;
    UiDock dock = UiDock::Fill;
    int preferredWidth = 0;
    int preferredHeight = 0;
    int minWidth = 0;
    int minHeight = 0;
    int maxWidth = 0;  // 0 = unlimited
    int maxHeight = 0;
    int compressionPriority = 50; // lower = shrink/collapse first
    bool visible = true;
    bool collapsible = false;
    bool canShrink = true;
    bool allowOverlap = false;
    int collapsedWidth = 0;
    int collapsedHeight = 0;
};

struct UiRegionState {
    UiRegionManifest manifest{};
    RECT requested{};
    RECT resolved{};
    HWND hwnd = nullptr;
    bool clipped = false;
    bool overlapped = false;
    bool collapsed = false;
    bool outOfParent = false;
    bool negativeDim = false;
    bool zeroSize = false;
};

inline int RectW(const RECT& r) { return r.right - r.left; }
inline int RectH(const RECT& r) { return r.bottom - r.top; }

inline bool RectValid(const RECT& r) {
    return RectW(r) >= 0 && RectH(r) >= 0;
}

inline bool RectsOverlap(const RECT& a, const RECT& b) {
    return a.left < b.right && a.right > b.left && a.top < b.bottom &&
           a.bottom > b.top;
}

inline bool ContainsRect(const RECT& parent, const RECT& child) {
    return child.left >= parent.left && child.top >= parent.top &&
           child.right <= parent.right && child.bottom <= parent.bottom;
}

inline RECT ClampRectTo(const RECT& r, const RECT& bounds) {
    RECT o = r;
    o.left = (std::max)(bounds.left, (std::min)(o.left, bounds.right));
    o.right = (std::max)(bounds.left, (std::min)(o.right, bounds.right));
    o.top = (std::max)(bounds.top, (std::min)(o.top, bounds.bottom));
    o.bottom = (std::max)(bounds.top, (std::min)(o.bottom, bounds.bottom));
    if (o.right < o.left) o.right = o.left;
    if (o.bottom < o.top) o.bottom = o.top;
    return o;
}

inline RECT TakeTop(RECT& avail, int height) {
    height = (std::clamp)(height, 0, (std::max)(0, RectH(avail)));
    RECT out{avail.left, avail.top, avail.right, avail.top + height};
    avail.top += height;
    return out;
}

inline RECT TakeBottom(RECT& avail, int height) {
    height = (std::clamp)(height, 0, (std::max)(0, RectH(avail)));
    RECT out{avail.left, avail.bottom - height, avail.right, avail.bottom};
    avail.bottom -= height;
    return out;
}

inline RECT TakeLeft(RECT& avail, int width) {
    width = (std::clamp)(width, 0, (std::max)(0, RectW(avail)));
    RECT out{avail.left, avail.top, avail.left + width, avail.bottom};
    avail.left += width;
    return out;
}

inline RECT TakeRight(RECT& avail, int width) {
    width = (std::clamp)(width, 0, (std::max)(0, RectW(avail)));
    RECT out{avail.right - width, avail.top, avail.right, avail.bottom};
    avail.right -= width;
    return out;
}

struct UiLayoutInputs {
    int clientW = 0;
    int clientH = 0;
    int toolbarH = 32;
    int statusH = 24;
    int activityW = 48;
    int leftSidebarW = 250;
    int rightSidebarW = 320;
    int tabH = 28;
    int breadcrumbH = 22;
    int gutterW = 0;
    int minimapW = 0;
    int terminalH = 220;
    int outputH = 0;
    bool showActivity = true;
    bool showLeft = true;
    bool showRight = true;
    bool showTabs = true;
    bool showBreadcrumbs = false;
    bool showGutter = false;
    bool showMinimap = false;
    bool showTerminal = true;
    bool showOutput = false;
    bool showStatus = true;
};

struct UiSpatialRegistry {
    std::unordered_map<UiRegionId, UiRegionState> regions;
    RECT client{};
    int overlapCount = 0;
    int outOfBoundsCount = 0;
    int negativeCount = 0;
    int zeroSizeCount = 0;
    bool valid = false;
    std::string report;

    UiRegionState& ensure(UiRegionId id) {
        auto& s = regions[id];
        s.manifest.id = id;
        return s;
    }

    void setHwnd(UiRegionId id, HWND hwnd) { ensure(id).hwnd = hwnd; }

    const RECT* resolved(UiRegionId id) const {
        auto it = regions.find(id);
        return it == regions.end() ? nullptr : &it->second.resolved;
    }
};

inline void SeedDefaultManifests(UiSpatialRegistry& ui) {
    auto M = [&](UiRegionId id, UiRegionId parent, UiDock dock, int pri,
                 bool collapsible = false) {
        auto& s = ui.ensure(id);
        s.manifest.parent = parent;
        s.manifest.dock = dock;
        s.manifest.compressionPriority = pri;
        s.manifest.collapsible = collapsible;
        s.manifest.canShrink = true;
        s.manifest.allowOverlap = false;
    };
    M(UiRegionId::Client, UiRegionId::Client, UiDock::Fill, 0);
    M(UiRegionId::MainToolbar, UiRegionId::Client, UiDock::Top, 90);
    M(UiRegionId::StatusBar, UiRegionId::Client, UiDock::Bottom, 95);
    M(UiRegionId::Terminal, UiRegionId::Client, UiDock::Bottom, 30, true);
    M(UiRegionId::Workspace, UiRegionId::Client, UiDock::Fill, 100);
    M(UiRegionId::ActivityBar, UiRegionId::Workspace, UiDock::Left, 80);
    M(UiRegionId::LeftSidebar, UiRegionId::Workspace, UiDock::Left, 20, true);
    M(UiRegionId::RightSidebar, UiRegionId::Workspace, UiDock::Right, 10, true);
    M(UiRegionId::AiChat, UiRegionId::RightSidebar, UiDock::Fill, 10);
    M(UiRegionId::EditorTabs, UiRegionId::Workspace, UiDock::Top, 85);
    M(UiRegionId::Breadcrumbs, UiRegionId::Workspace, UiDock::Top, 84);
    M(UiRegionId::EditorGutter, UiRegionId::Workspace, UiDock::Left, 70);
    M(UiRegionId::Editor, UiRegionId::Workspace, UiDock::Fill, 100);
    M(UiRegionId::Minimap, UiRegionId::Workspace, UiDock::Right, 40, true);
}

// Responsive collapse when client is too narrow/short.
inline void ResponsiveCollapse(UiLayoutInputs& in) {
    const int minEditorW = 200;
    const int minEditorH = 120;
    int chromeW = (in.showActivity ? in.activityW : 0) +
                  (in.showLeft ? in.leftSidebarW : 0) +
                  (in.showRight ? in.rightSidebarW : 0) +
                  (in.showGutter ? in.gutterW : 0) +
                  (in.showMinimap ? in.minimapW : 0);
    if (in.clientW - chromeW < minEditorW && in.showRight) {
        in.showRight = false;
        chromeW -= in.rightSidebarW;
    }
    if (in.clientW - chromeW < minEditorW && in.showLeft) {
        in.showLeft = false;
        chromeW -= in.leftSidebarW;
    }
    if (in.clientW - chromeW < minEditorW && in.showMinimap) {
        in.showMinimap = false;
    }
    int chromeH = in.toolbarH + (in.showStatus ? in.statusH : 0) +
                  (in.showTerminal ? in.terminalH : 0) +
                  (in.showOutput ? in.outputH : 0) +
                  (in.showTabs ? in.tabH : 0) +
                  (in.showBreadcrumbs ? in.breadcrumbH : 0);
    if (in.clientH - chromeH < minEditorH && in.showTerminal) {
        in.showTerminal = false;
        chromeH -= in.terminalH;
    }
    if (in.clientH - chromeH < minEditorH && in.showOutput) {
        in.showOutput = false;
    }
}

inline void ResolveSpatialManifest(UiSpatialRegistry& ui,
                                   const UiLayoutInputs& rawIn) {
    SeedDefaultManifests(ui);
    UiLayoutInputs in = rawIn;
    ResponsiveCollapse(in);

    ui.client = {0, 0, in.clientW, in.clientH};
    ui.ensure(UiRegionId::Client).resolved = ui.client;
    ui.ensure(UiRegionId::Client).manifest.visible = true;

    RECT avail = ui.client;

    // Outside → inside: Top, Bottom, then Workspace fill.
    auto& toolbar = ui.ensure(UiRegionId::MainToolbar);
    toolbar.manifest.visible = true;
    toolbar.manifest.preferredHeight = in.toolbarH;
    toolbar.resolved = TakeTop(avail, in.toolbarH);

    auto& status = ui.ensure(UiRegionId::StatusBar);
    status.manifest.visible = in.showStatus;
    if (in.showStatus)
        status.resolved = TakeBottom(avail, in.statusH);
    else
        status.resolved = {0, 0, 0, 0};

    auto& term = ui.ensure(UiRegionId::Terminal);
    term.manifest.visible = in.showTerminal;
    if (in.showTerminal)
        term.resolved = TakeBottom(avail, in.terminalH);
    else {
        term.resolved = {0, 0, 0, 0};
        term.collapsed = true;
    }

    // Optional output panel stacks above terminal (same bottom band family).
    if (in.showOutput && in.outputH > 0) {
        RECT out = TakeBottom(avail, in.outputH);
        // Stash in TerminalToolbar as sibling band marker (diagnostic).
        auto& ot = ui.ensure(UiRegionId::TerminalToolbar);
        ot.manifest.visible = true;
        ot.resolved = out;
    }

    auto& workspace = ui.ensure(UiRegionId::Workspace);
    workspace.manifest.visible = true;
    workspace.resolved = avail;

    RECT ws = avail;

    auto& activity = ui.ensure(UiRegionId::ActivityBar);
    activity.manifest.visible = in.showActivity;
    if (in.showActivity)
        activity.resolved = TakeLeft(ws, in.activityW);
    else
        activity.resolved = {0, 0, 0, 0};

    auto& left = ui.ensure(UiRegionId::LeftSidebar);
    left.manifest.visible = in.showLeft;
    if (in.showLeft)
        left.resolved = TakeLeft(ws, in.leftSidebarW);
    else {
        left.resolved = {0, 0, 0, 0};
        left.collapsed = true;
    }

    auto& right = ui.ensure(UiRegionId::RightSidebar);
    right.manifest.visible = in.showRight;
    if (in.showRight)
        right.resolved = TakeRight(ws, in.rightSidebarW);
    else {
        right.resolved = {0, 0, 0, 0};
        right.collapsed = true;
    }
    ui.ensure(UiRegionId::AiChat).manifest.visible = in.showRight;
    ui.ensure(UiRegionId::AiChat).resolved = right.resolved;

    auto& tabs = ui.ensure(UiRegionId::EditorTabs);
    tabs.manifest.visible = in.showTabs;
    if (in.showTabs)
        tabs.resolved = TakeTop(ws, in.tabH);
    else
        tabs.resolved = {0, 0, 0, 0};

    auto& crumbs = ui.ensure(UiRegionId::Breadcrumbs);
    crumbs.manifest.visible = in.showBreadcrumbs;
    if (in.showBreadcrumbs)
        crumbs.resolved = TakeTop(ws, in.breadcrumbH);
    else
        crumbs.resolved = {0, 0, 0, 0};

    auto& gutter = ui.ensure(UiRegionId::EditorGutter);
    gutter.manifest.visible = in.showGutter && in.gutterW > 0;
    if (gutter.manifest.visible)
        gutter.resolved = TakeLeft(ws, in.gutterW);
    else
        gutter.resolved = {0, 0, 0, 0};

    auto& mini = ui.ensure(UiRegionId::Minimap);
    mini.manifest.visible = in.showMinimap && in.minimapW > 0;
    if (mini.manifest.visible)
        mini.resolved = TakeRight(ws, in.minimapW);
    else
        mini.resolved = {0, 0, 0, 0};

    auto& editor = ui.ensure(UiRegionId::Editor);
    editor.manifest.visible = true;
    editor.resolved = ws; // FILL — remaining only

    // Clamp all to client
    for (auto& kv : ui.regions) {
        if (kv.first == UiRegionId::Client) continue;
        if (!kv.second.manifest.visible) continue;
        kv.second.resolved = ClampRectTo(kv.second.resolved, ui.client);
    }
}

inline void ValidateSpatialLayout(UiSpatialRegistry& ui) {
    ui.overlapCount = 0;
    ui.outOfBoundsCount = 0;
    ui.negativeCount = 0;
    ui.zeroSizeCount = 0;

    std::vector<UiRegionId> ids;
    for (auto& kv : ui.regions)
        ids.push_back(kv.first);

    for (auto id : ids) {
        auto& s = ui.regions[id];
        s.overlapped = false;
        s.outOfParent = false;
        s.negativeDim = false;
        s.zeroSize = false;
        if (!s.manifest.visible) continue;

        if (!RectValid(s.resolved) || RectW(s.resolved) < 0 ||
            RectH(s.resolved) < 0) {
            s.negativeDim = true;
            ++ui.negativeCount;
        }
        if (RectW(s.resolved) == 0 || RectH(s.resolved) == 0) {
            // Collapsed optional regions may be zero — only count if required fill/editor
            if (id == UiRegionId::Editor || id == UiRegionId::Workspace) {
                s.zeroSize = true;
                ++ui.zeroSizeCount;
            }
        }
        if (s.manifest.parent != id) {
            auto pit = ui.regions.find(s.manifest.parent);
            if (pit != ui.regions.end() && pit->second.manifest.visible) {
                if (!ContainsRect(pit->second.resolved, s.resolved) &&
                    RectW(s.resolved) > 0 && RectH(s.resolved) > 0) {
                    s.outOfParent = true;
                    ++ui.outOfBoundsCount;
                }
            }
        }
    }

    // Sibling overlap within same parent (Workspace children + Client chrome).
    for (size_t i = 0; i < ids.size(); ++i) {
        auto& a = ui.regions[ids[i]];
        if (!a.manifest.visible || a.manifest.allowOverlap) continue;
        if (RectW(a.resolved) <= 0 || RectH(a.resolved) <= 0) continue;
        for (size_t j = i + 1; j < ids.size(); ++j) {
            auto& b = ui.regions[ids[j]];
            if (!b.manifest.visible || b.manifest.allowOverlap) continue;
            if (a.manifest.parent != b.manifest.parent) continue;
            // Parent/child pairs share parent id differently — skip Client vs children
            if (ids[i] == UiRegionId::Client || ids[j] == UiRegionId::Client)
                continue;
            if (ids[i] == UiRegionId::Workspace || ids[j] == UiRegionId::Workspace)
                continue;
            if (RectW(b.resolved) <= 0 || RectH(b.resolved) <= 0) continue;
            if (RectsOverlap(a.resolved, b.resolved)) {
                a.overlapped = true;
                b.overlapped = true;
                ++ui.overlapCount;
            }
        }
    }

    ui.valid = (ui.overlapCount == 0 && ui.outOfBoundsCount == 0 &&
                ui.negativeCount == 0 && ui.zeroSizeCount == 0);

    char buf[256];
    std::snprintf(buf, sizeof(buf),
                  "UI_SPATIAL overlaps=%d oob=%d neg=%d zero=%d valid=%s",
                  ui.overlapCount, ui.outOfBoundsCount, ui.negativeCount,
                  ui.zeroSizeCount, ui.valid ? "YES" : "NO");
    ui.report = buf;
}

inline int ApplySpatialLayout(UiSpatialRegistry& ui) {
    if (!ui.valid) {
        // Still apply clamped rects fail-soft, but callers may skip.
    }
    int count = 0;
    for (auto& kv : ui.regions)
        if (kv.second.hwnd && IsWindow(kv.second.hwnd) && kv.second.manifest.visible)
            ++count;
    if (count <= 0) return 0;

    HDWP hdwp = BeginDeferWindowPos(count);
    if (!hdwp) return 0;

    for (auto& kv : ui.regions) {
        auto& s = kv.second;
        if (!s.hwnd || !IsWindow(s.hwnd) || !s.manifest.visible) continue;
        const RECT& r = s.resolved;
        const int w = (std::max)(0, RectW(r));
        const int h = (std::max)(0, RectH(r));
        hdwp = DeferWindowPos(hdwp, s.hwnd, nullptr, r.left, r.top, w, h,
                              SWP_NOZORDER | SWP_NOACTIVATE);
        if (!hdwp) return 0;
    }
    EndDeferWindowPos(hdwp);
    return count;
}

inline const char* UiRegionName(UiRegionId id) {
    switch (id) {
    case UiRegionId::Client: return "CLIENT";
    case UiRegionId::MainToolbar: return "TOOLBAR";
    case UiRegionId::ActivityBar: return "ACTIVITY";
    case UiRegionId::LeftSidebar: return "LEFT_SIDEBAR";
    case UiRegionId::RightSidebar: return "RIGHT_SIDEBAR";
    case UiRegionId::AiChat: return "AI_CHAT";
    case UiRegionId::EditorTabs: return "EDITOR_TABS";
    case UiRegionId::Breadcrumbs: return "BREADCRUMBS";
    case UiRegionId::EditorGutter: return "GUTTER";
    case UiRegionId::Editor: return "EDITOR";
    case UiRegionId::Minimap: return "MINIMAP";
    case UiRegionId::Terminal: return "TERMINAL";
    case UiRegionId::StatusBar: return "STATUS";
    case UiRegionId::CommandHost: return "COMMAND_HOST";
    case UiRegionId::CommandLeftRail: return "CMD_LEFT_RAIL";
    case UiRegionId::TopContextBar: return "CMD_CONTEXT";
    case UiRegionId::CommandConversation: return "CMD_CONVERSATION";
    case UiRegionId::ActivityStrip: return "CMD_ACTIVITY";
    case UiRegionId::CommandComposer: return "CMD_COMPOSER";
    case UiRegionId::CommandFooter: return "CMD_FOOTER";
    case UiRegionId::Workspace: return "WORKSPACE";
    default: return "REGION";
    }
}

} // namespace Ui
} // namespace RawrXD
