#include "editor_api.hpp"
#include <cstdio>
#include <windows.h>

static HWND gOwner = nullptr, gPanel = nullptr, gList = nullptr;
static HWND gEdit[8]{};
static HBRUSH gBrush = nullptr;
static int gWidth = 300;
static const wchar_t* kClass = L"RawrInspector";
enum { ID_LIST = 1001, ID_X = 1010, ID_APPLY = 1020, ID_RAISE = 1040, ID_UNDO = 1050, ID_REDO = 1051 };
void inspectorOnCommand(int id);

static LRESULT CALLBACK inspectorProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_COMMAND) inspectorOnCommand(LOWORD(wp));
    if (msg == WM_CTLCOLOREDIT || msg == WM_CTLCOLORSTATIC || msg == WM_CTLCOLORLISTBOX || msg == WM_CTLCOLORBTN) {
        SetTextColor(reinterpret_cast<HDC>(wp), RGB(229, 231, 235));
        SetBkColor(reinterpret_cast<HDC>(wp), RGB(21, 25, 39));
        return reinterpret_cast<LRESULT>(gBrush);
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}
HWND inspectorEdit(int index) { return (index >= 0 && index < 8) ? gEdit[index] : nullptr; }
HWND inspectorList() { return gList; }
HWND inspectorPanel() { return gPanel; }
HWND inspectorOwner() { return gOwner; }
int inspectorWidth() { return gWidth; }
void inspectorSetWidth(int width) {
    if (width < 220 || width > 520) return;
    gWidth = width;
    FILE* f = nullptr;
    fopen_s(&f, "F:/rawrxd/kartgib/evidence/studio_project/layout.txt", "w");
    if (f) { std::fprintf(f, "%d\n", gWidth); std::fclose(f); }
}
void inspectorLayout(int width, int height) {
    (void)width; (void)height;
    if (!gPanel || !gOwner || GetParent(gPanel) == gOwner) return;
    RECT rc{}; GetWindowRect(gOwner, &rc);
    int h = rc.bottom - rc.top; if (h < 200) return;
    RECT cur{}; GetWindowRect(gPanel, &cur);
    if (cur.left == rc.right + 8 && cur.top == rc.top && cur.right - cur.left == gWidth && cur.bottom - cur.top == h) return;
    SetWindowPos(gPanel, HWND_TOP, rc.right + 8, rc.top, gWidth, h, SWP_NOACTIVATE | SWP_SHOWWINDOW);
}
void inspectorCreate(HWND parent) {
    if (gPanel) return;
    gOwner = parent;
    FILE* f = nullptr;
    fopen_s(&f, "F:/rawrxd/kartgib/evidence/studio_project/layout.txt", "r");
    if (f) { int w = 0; if (std::fscanf(f, "%d", &w) == 1) inspectorSetWidth(w); std::fclose(f); }
    gBrush = CreateSolidBrush(RGB(21, 25, 39));
    WNDCLASSW wc{}; wc.lpfnWndProc = inspectorProc; wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kClass; wc.hbrBackground = gBrush; RegisterClassW(&wc);
    gPanel = CreateWindowExW(WS_EX_TOOLWINDOW, kClass, L"Terrain Inspector",
        WS_OVERLAPPED | WS_CAPTION | WS_VISIBLE, 40, 40, gWidth, 640, parent, nullptr, wc.hInstance, nullptr);
    const wchar_t* labels[] = {L"X", L"Y", L"Z", L"Yaw", L"Scale", L"Radius", L"Strength", L"Falloff"};
    for (int i = 0; i < 8; ++i) {
        int y = 8 + i * 28;
        CreateWindowExW(0, L"STATIC", labels[i], WS_CHILD | WS_VISIBLE, 12, y, 78, 20, gPanel, nullptr, wc.hInstance, nullptr);
        gEdit[i] = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"0", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
            96, y, 160, 22, gPanel, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_X + i)), wc.hInstance, nullptr);
    }
    CreateWindowExW(0, L"BUTTON", L"Apply", WS_CHILD | WS_VISIBLE, 12, 240, 100, 26, gPanel, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_APPLY)), wc.hInstance, nullptr);
    const wchar_t* modes[] = {L"Raise", L"Lower", L"Smooth", L"Flatten"};
    for (int i = 0; i < 4; ++i)
        CreateWindowExW(0, L"BUTTON", modes[i], WS_CHILD | WS_VISIBLE, 12 + (i % 2) * 120, 276 + (i / 2) * 30, 110, 26,
            gPanel, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_RAISE + i)), wc.hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Undo", WS_CHILD | WS_VISIBLE, 12, 346, 100, 26, gPanel, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_UNDO)), wc.hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Redo", WS_CHILD | WS_VISIBLE, 122, 346, 100, 26, gPanel, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_REDO)), wc.hInstance, nullptr);
    gList = CreateWindowExW(0, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL,
        12, 386, 250, 180, gPanel, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_LIST)), wc.hInstance, nullptr);
    inspectorLayout(0, 0);
    inspectorArmDock();
}
