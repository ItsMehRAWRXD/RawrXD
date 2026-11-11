#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include "win32_window.hpp"
#include <cmath>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

static const char* kDir = "F:/rawrxd/kartgib/evidence/studio_project";
static void click(int id) { SendMessageW(GetParent(inspectorEdit(0)), WM_COMMAND, id, 0); }
static int reloadChild(float mesh, float x, float radius, int width, float yaw, float scale) {
    wchar_t exe[32768]{}; GetModuleFileNameW(nullptr, exe, 32768);
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --studio-load";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) return 0;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 1; GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    std::ifstream in("F:/rawrxd/kartgib/evidence/studio_peak.txt");
    float my = 0, mx = 0, mr = 0, myaw = 0, mscale = 0; int mw = 0;
    in >> my >> mx >> mr >> mw >> myaw >> mscale;
    return code == 0 && std::fabs(my - mesh) < 0.05f && std::fabs(mx - x) < 0.05f
        && std::fabs(mr - radius) < 0.05f && mw == width
        && std::fabs(myaw - yaw) < 0.05f && std::fabs(mscale - scale) < 0.05f;
}
bool inspectorLate(Win32Window& window, VulkanRenderer& renderer, int phase) {
    const EditorEnt* e = editorAt(0);
    switch (phase) {
    case 3:
        std::cout << "[INSPECTOR] height " << studioBaseY() << " -> " << studioMeshY() << std::endl;
        sunshineScene("transform 1 9 18 24 0 1");
        inspectorRefresh();
        std::cout << "[INSPECTOR] sunshine x=" << (e ? e->x : 0) << std::endl;
        renderer.requestEditorShot("gui_sunshine");
        return true;
    case 4:
        click(1050); click(1050);
        std::cout << "[INSPECTOR] undo_clicks x=" << (e ? e->x : 0) << std::endl;
        return true;
    case 5:
        std::cout << "[INSPECTOR] terrain_undo y=" << studioMeshY() << std::endl;
        renderer.requestEditorShot("gui_undo");
        return true;
    case 6:
        click(1051);
        return true;
    case 7:
        std::cout << "[INSPECTOR] terrain_redo y=" << studioMeshY() << " x=" << (e ? e->x : 0) << std::endl;
        renderer.requestEditorShot("gui_redo");
        click(1051);
        return true;
    case 8:
        studioShiftCamera(90.0f);
        renderer.requestEditorShot("gui_camera");
        std::cout << "[INSPECTOR] camera=" << studioCameraShift() << std::endl;
        return true;
    case 9:
        editorTap(window, 'P'); editorHandleInput(window);
        editorPlayStep();
        std::cout << "[INSPECTOR] play=" << editorPlaying() << " z=" << (e ? e->z : 0)
                  << " mesh=" << studioMeshY() << std::endl;
        editorTap(window, 'P'); editorHandleInput(window);
        return true;
    case 10:
        SendMessage(window.getHandle(), WM_SIZE, 0, MAKELPARAM(1100, 640));
        std::cout << "[INSPECTOR] resize=" << window.getWidth() << "x" << window.getHeight() << std::endl;
        return true;
    default:
        SendMessage(window.getHandle(), WM_SIZE, 0, MAKELPARAM(1280, 720));
        studioShiftCamera(0.0f);
        bool saved = studioSaveProject(kDir);
        int child = reloadChild(studioMeshY(), e ? e->x : 0, studioBrush().radius, inspectorWidth(),
            e ? e->yaw : 0, e ? e->scale : 0);
        std::cout << "[INSPECTOR] save=" << saved << " reload=" << child
                  << " y=" << studioMeshY() << " x=" << (e ? e->x : 0) << std::endl;
        editorMarkDone();
        return false;
    }
}
