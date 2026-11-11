#include "editor_api.hpp"
#include "win32_window.hpp"
#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
static void click(int id) { SendMessageW(GetParent(inspectorEdit(0)), WM_COMMAND, id, 0); }
static int gold(const char* name) {
    for (int i = 0; i < editorShotCount(); ++i)
        if (!std::strcmp(editorShotAt(i)->name, name)) return editorShotAt(i)->gold;
    return -1;
}
static void selectId(Win32Window& window, int id) {
    editorTap(window, 'T'); editorHandleInput(window);
    int px = 0, py = 0; editorProjectId(window, id, -1, px, py);
    editorDrag(window, px, py, px, py); editorHandleInput(window);
}
static bool pose(int id, float x, float y, float z, float yaw, float scale) {
    const EditorEnt* e = editorFind(id); if (!e) return false;
    return std::fabs(e->x - x) < 0.05f && std::fabs(e->y - y) < 0.05f && std::fabs(e->z - z) < 0.05f
        && std::fabs(e->yaw - yaw) < 0.05f && std::fabs(e->scale - scale) < 0.05f;
}
static int reloadChild() {
    wchar_t exe[32768]{}; GetModuleFileNameW(nullptr, exe, 32768);
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --studio-editor2-load";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) return 0;
    WaitForSingleObject(pi.hProcess, 45000);
    DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    std::ifstream in("F:/rawrxd/kartgib/evidence/studio_editor2_peak.txt");
    int id = 0, parent = 0, id2 = 0, parent2 = 0, dock = -1, lx, ly, lw, lh;
    float x, y, z, yaw, scale, a, b, c, d, e; std::string tag;
    if (!(in >> id >> parent >> x >> y >> z >> yaw >> scale)) return 0;
    if (!(in >> id2 >> parent2 >> a >> b >> c >> d >> e)) return 0;
    if (!(in >> tag >> dock >> lx >> ly >> lw >> lh)) return 0;
    const EditorEnt* one = editorFind(1); const EditorEnt* two = editorFind(2);
    return code == 0 && one && two && id == 1 && id2 == 2 && parent == one->parent && parent2 == two->parent
        && std::fabs(x - one->x) < 0.05f && std::fabs(yaw - one->yaw) < 0.05f && std::fabs(scale - one->scale) < 0.05f
        && std::fabs(a - two->x) < 0.05f && dock == 1;
}
bool editor2Script(Win32Window& window, VulkanRenderer& renderer) {
    if (renderer.editorShotBusy()) return true;
    static int frames = 0; if (frames++ < 3) return true;
    static int phase = 0;
    static float x0, y0, z0, yaw0, s0, x2, y2, z2, yaw2, s2;
    switch (phase++) {
    case 0: studioCreateProject("F:/rawrxd/kartgib/evidence/studio_project"); inspectorDock(); renderer.requestEditorShot("e2_base"); break;
    case 1: selectId(window, 1); renderer.requestEditorShot("e2_sel"); break;
    case 2: std::cout << "[E2] gold " << gold("e2_base") << " " << gold("e2_sel") << std::endl; selectId(window, 2); renderer.requestEditorShot("e2_b"); break;
    case 3: {
        std::cout << "[E2] gold2 " << gold("e2_b") << " selected=" << editorSelected() << std::endl;
        selectId(window, 1);
        float before = editorFind(1)->x; editorGesture(window, 'T', 0, 90); float mid = editorFind(1)->x;
        editorGesture(window, 0, 0, 90); float after = editorFind(1)->x; editorUndo();
        editorGesture(window, 'R', 0, 80); editorGesture(window, 'S', 0, 50);
        const EditorEnt* e = editorFind(1); const EditorEnt* o = editorFind(2);
        x0 = e->x; y0 = e->y; z0 = e->z; yaw0 = e->yaw; s0 = e->scale; x2 = o->x; y2 = o->y; z2 = o->z; yaw2 = o->yaw; s2 = o->scale;
        std::cout << "[E2] gizmo " << before << " " << mid << " " << after << " " << e->x << " yaw=" << e->yaw << " scale=" << e->scale << std::endl;
        break;
    }
    case 4: {
        selectId(window, 2); click(1060); inspectorRefresh();
        wchar_t line[64]{}; SendMessageW(inspectorList(), LB_GETTEXT, 1, reinterpret_cast<LPARAM>(line));
        std::wcout << L"[E2] parent=" << editorFind(2)->parent << L" list=" << line
                   << L" keep=" << pose(1, x0, y0, z0, yaw0, s0) << pose(2, x2, y2, z2, yaw2, s2) << std::endl;
        click(1061);
        std::cout << "[E2] unparent=" << editorFind(2)->parent << " keep=" << pose(2, x2, y2, z2, yaw2, s2) << std::endl;
        selectId(window, 1); click(1060);
        std::cout << "[E2] reparent=" << editorFind(1)->parent << " keep=" << pose(1, x0, y0, z0, yaw0, s0) << std::endl;
        editorUndo(); std::cout << "[E2] undo_parent=" << editorFind(1)->parent << std::endl;
        editorRedo(); std::cout << "[E2] redo_parent=" << editorFind(1)->parent << std::endl;
        break;
    }
    case 5: {
        int d, x, y, w, h; inspectorDockInfo(d, x, y, w, h); std::cout << "[E2] dock " << d << " " << w << " " << h << std::endl;
        inspectorDetach(); inspectorDockInfo(d, x, y, w, h); std::cout << "[E2] detach " << d << " " << x << " " << y << " " << w << " " << h << std::endl;
        inspectorNudge(40, 24, 410, 600); inspectorDockInfo(d, x, y, w, h); std::cout << "[E2] nudge " << x << " " << y << " " << w << " " << h << std::endl;
        inspectorDock(); inspectorDockInfo(d, x, y, w, h); std::cout << "[E2] redock " << d << " " << w << std::endl;
        break;
    }
    default:
        std::cout << "[E2] save=" << studioSaveProject("F:/rawrxd/kartgib/evidence/studio_project")
                  << " reload=" << reloadChild() << std::endl;
        editorMarkDone(); return false;
    }
    return true;
}
