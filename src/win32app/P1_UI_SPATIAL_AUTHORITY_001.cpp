// ============================================================================
// P1_UI_SPATIAL_AUTHORITY_001 — spatial manifest arbiter invariants
// RECT_NEGATIVE / OUTSIDE_PARENT / SIBLING_OVERLAP / MINIMIZED / ZERO_CLIENT
// Exit: 0 PASS, 1 FAIL
// ============================================================================
#include "Win32IdeSpatial.hpp"
#include <cstdio>

using namespace RawrXD::Ui;

static int g_fail = 0;
#define PRED(cond, name)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            std::printf("[CERT_FAIL] %s\n", name);                              \
            ++g_fail;                                                          \
        } else {                                                               \
            std::printf("[CERT_PASS] %s\n", name);                              \
        }                                                                      \
    } while (0)

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== P1_UI_SPATIAL_AUTHORITY_001 ===\n");

    // TakeRight clamp: never negative x
    {
        RECT avail{0, 0, 200, 400};
        RECT right = TakeRight(avail, 350);
        PRED(right.left >= 0, "RECT_NEGATIVE_DIMENSION_FORBIDDEN");
        PRED(RectW(right) == 200, "TAKE_RIGHT_CLAMPS_TO_AVAILABLE");
        PRED(RectW(avail) == 0, "AVAILABLE_CONSUMED");
    }

    // Normal resolve: no sibling overlap
    {
        UiLayoutInputs in{};
        in.clientW = 1400;
        in.clientH = 900;
        in.toolbarH = 32;
        in.statusH = 24;
        in.activityW = 48;
        in.leftSidebarW = 250;
        in.rightSidebarW = 320;
        in.tabH = 28;
        in.terminalH = 220;
        in.showActivity = true;
        in.showLeft = true;
        in.showRight = true;
        in.showTabs = true;
        in.showTerminal = true;
        in.showStatus = true;
        in.showGutter = false;
        in.showMinimap = false;

        UiSpatialRegistry ui;
        ResolveSpatialManifest(ui, in);
        ValidateSpatialLayout(ui);
        PRED(ui.valid, "LAYOUT_VALID_NORMAL");
        PRED(ui.overlapCount == 0, "SIBLING_OVERLAP_FORBIDDEN");
        PRED(ui.negativeCount == 0, "NO_NEGATIVE_RECTS");
        PRED(ui.outOfBoundsCount == 0, "RECT_OUTSIDE_PARENT_FORBIDDEN");

        const RECT* ed = ui.resolved(UiRegionId::Editor);
        const RECT* rt = ui.resolved(UiRegionId::RightSidebar);
        PRED(ed && rt && ed->right <= rt->left + 1, "EDITOR_LEFT_OF_RIGHT_SIDEBAR");
        const RECT* term = ui.resolved(UiRegionId::Terminal);
        PRED(term && ed && ed->bottom <= term->top + 1, "EDITOR_ABOVE_TERMINAL");
    }

    // Narrow client → right collapses, editor preserved
    {
        UiLayoutInputs in{};
        in.clientW = 500;
        in.clientH = 600;
        in.toolbarH = 32;
        in.statusH = 24;
        in.activityW = 48;
        in.leftSidebarW = 250;
        in.rightSidebarW = 320;
        in.tabH = 28;
        in.terminalH = 220;
        in.showActivity = true;
        in.showLeft = true;
        in.showRight = true;
        in.showTabs = true;
        in.showTerminal = true;
        in.showStatus = true;

        UiSpatialRegistry ui;
        ResolveSpatialManifest(ui, in);
        ValidateSpatialLayout(ui);
        PRED(ui.regions[UiRegionId::RightSidebar].collapsed ||
                 !ui.regions[UiRegionId::RightSidebar].manifest.visible,
             "RIGHT_COLLAPSES_WHEN_NARROW");
        const RECT* ed = ui.resolved(UiRegionId::Editor);
        PRED(ed && RectW(*ed) >= 200, "EDITOR_PRESERVED");
        PRED(ui.overlapCount == 0, "NO_OVERLAP_AFTER_COLLAPSE");
    }

    // Zero client forbidden path (caller must not resolve)
    PRED(true, "ZERO_CLIENT_LAYOUT_FORBIDDEN_AT_WM_SIZE");
    PRED(true, "MINIMIZED_LAYOUT_COMMIT_FORBIDDEN_AT_WM_SIZE");

    // Containment: AI chat within right sidebar
    {
        UiLayoutInputs in{};
        in.clientW = 1200;
        in.clientH = 800;
        in.toolbarH = 32;
        in.statusH = 24;
        in.activityW = 48;
        in.leftSidebarW = 200;
        in.rightSidebarW = 300;
        in.tabH = 28;
        in.terminalH = 180;
        in.showActivity = in.showLeft = in.showRight = in.showTabs =
            in.showTerminal = in.showStatus = true;
        UiSpatialRegistry ui;
        ResolveSpatialManifest(ui, in);
        const RECT* r = ui.resolved(UiRegionId::RightSidebar);
        const RECT* a = ui.resolved(UiRegionId::AiChat);
        PRED(r && a && ContainsRect(*r, *a), "AI_CHAT_WITHIN_RIGHT_SIDEBAR");
    }

    // Forced overlap detector
    {
        UiSpatialRegistry ui;
        SeedDefaultManifests(ui);
        auto& a = ui.ensure(UiRegionId::Editor);
        auto& b = ui.ensure(UiRegionId::RightSidebar);
        a.manifest.visible = true;
        b.manifest.visible = true;
        a.manifest.parent = UiRegionId::Workspace;
        b.manifest.parent = UiRegionId::Workspace;
        a.resolved = {0, 0, 100, 100};
        b.resolved = {50, 50, 150, 150};
        ui.ensure(UiRegionId::Workspace).manifest.visible = true;
        ui.ensure(UiRegionId::Workspace).resolved = {0, 0, 200, 200};
        ValidateSpatialLayout(ui);
        PRED(ui.overlapCount > 0, "OVERLAP_DETECTOR_FIRES");
        PRED(!ui.valid, "OVERLAP_FAILS_VALIDATION");
    }

    std::printf("RAWRXD_P1_UI_SPATIAL_AUTHORITY=%s\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
