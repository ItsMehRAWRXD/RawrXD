#include "editor_api.hpp"
#include <cstdio>
#include <windows.h>
static int gDock = 1, gX = 40, gY = 40, gW = 340, gH = 640;
static void remember() {
    HWND panel = inspectorPanel(); if (!panel) return;
    RECT rc{}; GetWindowRect(panel, &rc);
    gX = rc.left; gY = rc.top; gW = rc.right - rc.left; gH = rc.bottom - rc.top;
}
static void save() {
    FILE* f = nullptr;
    fopen_s(&f, "F:/rawrxd/kartgib/evidence/studio_editor2_layout.txt", "w");
    if (!f) return;
    std::fprintf(f, "%d %d %d %d %d\n", gDock, gX, gY, gW, gH);
    std::fclose(f);
}
void inspectorDockInfo(int& docked, int& x, int& y, int& w, int& h) {
    remember(); docked = gDock; x = gX; y = gY; w = gW; h = gH;
}
void inspectorDock() {
    HWND panel = inspectorPanel(), owner = inspectorOwner(); if (!panel || !owner) return;
    SetWindowLongPtrW(panel, GWL_STYLE, WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN);
    SetParent(panel, owner);
    RECT rc{}; GetClientRect(owner, &rc);
    MoveWindow(panel, rc.right - 320, 0, 320, rc.bottom, TRUE);
    gDock = 1; remember(); save();
}
void inspectorDetach() {
    HWND panel = inspectorPanel(); if (!panel) return;
    SetParent(panel, nullptr);
    SetWindowLongPtrW(panel, GWL_STYLE, WS_OVERLAPPED | WS_CAPTION | WS_THICKFRAME | WS_VISIBLE);
    SetWindowPos(panel, HWND_TOP, 90, 70, 360, 560, SWP_FRAMECHANGED | SWP_SHOWWINDOW);
    gDock = 0; remember(); save();
}
void inspectorNudge(int dx, int dy, int w, int h) {
    HWND panel = inspectorPanel(); if (!panel) return;
    remember();
    SetWindowPos(panel, HWND_TOP, gX + dx, gY + dy, w, h, SWP_SHOWWINDOW);
    remember(); save();
}
void inspectorApplyEditor2() {
    FILE* f = nullptr;
    fopen_s(&f, "F:/rawrxd/kartgib/evidence/studio_editor2_layout.txt", "r");
    int docked = 1, x = 40, y = 40, w = 340, h = 640;
    if (f) { std::fscanf(f, "%d %d %d %d %d", &docked, &x, &y, &w, &h); std::fclose(f); }
    if (docked) { inspectorDock(); return; }
    HWND panel = inspectorPanel(); if (!panel) return;
    SetParent(panel, nullptr);
    SetWindowLongPtrW(panel, GWL_STYLE, WS_OVERLAPPED | WS_CAPTION | WS_THICKFRAME | WS_VISIBLE);
    SetWindowPos(panel, HWND_TOP, x, y, w, h, SWP_FRAMECHANGED | SWP_SHOWWINDOW);
    gDock = 0; remember();
}
void inspectorArmDock() {
    HWND panel = inspectorPanel(); if (!panel || GetDlgItem(panel, 1060)) return;
    HINSTANCE inst = GetModuleHandleW(nullptr);
    auto id = [](int value) { return reinterpret_cast<HMENU>(static_cast<INT_PTR>(value)); };
    CreateWindowExW(0, L"BUTTON", L"Parent", WS_CHILD | WS_VISIBLE, 12, 430, 100, 26, panel, id(1060), inst, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Unparent", WS_CHILD | WS_VISIBLE, 122, 430, 100, 26, panel, id(1061), inst, nullptr);
}
