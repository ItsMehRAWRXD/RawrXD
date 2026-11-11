#include "editor_api.hpp"
#include "win32_window.hpp"
#include <windows.h>
#include <cmath>
#include <cstdio>
#include <cstring>

void editorGit(char* rev, int n, char* dirty) {
    std::memcpy(rev, "UNVERSIONED", 12);
    std::memcpy(dirty, "UNKNOWN", 8);
    FILE* git = _popen("git -C F:/rawrxd/kartgib rev-parse HEAD", "r");
    if (git) {
        if (fgets(rev, n, git)) for (char* p = rev; *p; ++p) if (*p == '\n' || *p == '\r') *p = 0;
        _pclose(git);
    }
    FILE* st = _popen("git -C F:/rawrxd/kartgib status --porcelain", "r");
    if (st) { char t[4]{}; std::memcpy(dirty, fgets(t, 4, st) ? "DIRTY" : "CLEAN", 6); _pclose(st); }
}
void editorTap(Win32Window& window, int vk) {
    HWND hwnd = window.getHandle();
    SendMessage(hwnd, WM_KEYDOWN, vk, 0);
    SendMessage(hwnd, WM_KEYUP, vk, 0);
}
void editorDrag(Win32Window& window, int x0, int y0, int x1, int y1) {
    HWND hwnd = window.getHandle();
    SendMessage(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, MAKELPARAM(x0, y0));
    SendMessage(hwnd, WM_MOUSEMOVE, MK_LBUTTON, MAKELPARAM(x1, y1));
    SendMessage(hwnd, WM_LBUTTONUP, 0, MAKELPARAM(x1, y1));
}
bool editorProjectId(Win32Window& window, int id, int axis, int& px, int& py) {
    const EditorEnt* e = nullptr;
    for (int i = 0; i < editorCount(); ++i) if (editorAt(i)->id == id) e = editorAt(i);
    if (!e) return false;
    float view[16], proj[16], depth = 0, dx = 0, dy = 0, dz = 0;
    editorCamera(view, proj, window.getWidth(), window.getHeight());
    float dist = axis < 0 ? 0 : (editorGizmoMode() == 2 ? 5.0f : 6.0f);
    if (axis >= 0) editorAxis(axis, dx, dy, dz);
    return editorProject(view, proj, e->x + dx * dist, e->y + dy * dist, e->z + dz * dist,
        window.getWidth(), window.getHeight(), px, py, depth);
}
void editorGesture(Win32Window& window, int modeKey, int axis, int extraX) {
    if (modeKey) editorTap(window, modeKey);
    editorHandleInput(window);
    int hx = 0, hy = 0, cx = 0, cy = 0;
    if (!editorProjectId(window, 1, axis, hx, hy) || !editorProjectId(window, 1, -1, cx, cy)) return;
    int mx = hx - cx, my = hy - cy;
    float len = std::sqrt(static_cast<float>(mx * mx + my * my));
    int x1 = extraX ? hx + extraX : hx + (len > 1 ? static_cast<int>(mx / len * 140) : 140);
    int y1 = extraX ? hy : hy + (len > 1 ? static_cast<int>(my / len * 140) : 0);
    editorDrag(window, hx, hy, x1, y1);
    editorHandleInput(window);
}
