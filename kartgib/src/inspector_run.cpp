#include "editor_api.hpp"
#include "terrain_studio.hpp"
#include "win32_window.hpp"
#include "worldforge.hpp"
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
bool inspectorScript(Win32Window& window, VulkanRenderer& renderer) {
    if (renderer.editorShotBusy()) return true;
    static int frames = 0;
    if (frames++ < 3) return true;
    static int phase = 0;
    HWND xEdit = inspectorEdit(0);
    switch (phase++) {
    case 0:
        std::cout << "[INSPECTOR] project=" << studioCreateProject(kDir) << " panel=" << (xEdit ? 1 : 0)
                  << " capture=" << inspectorCapture("F:/rawrxd/kartgib/evidence/studio_inspector.bmp") << std::endl;
        inspectorSetWidth(340); inspectorLayout(window.getWidth(), window.getHeight());
        renderer.requestEditorShot("gui_ground");
        break;
    case 1: {
        editorTap(window, 'T'); editorHandleInput(window);
        int px = 0, py = 0; editorProjectId(window, 1, -1, px, py);
        editorDrag(window, px, py, px, py); editorHandleInput(window);
        inspectorRefresh();
        wchar_t text[32]{}; GetWindowTextW(xEdit, text, 32);
        std::wcout << L"[INSPECTOR] selected=" << editorSelected() << L" field=" << text << std::endl;
        SetWindowTextW(xEdit, L"22.00");
        SetWindowTextW(inspectorEdit(3), L"0.50");
        SetWindowTextW(inspectorEdit(4), L"1.40");
        click(1020); inspectorRefresh();
        std::cout << "[INSPECTOR] applied x=" << editorAt(0)->x
                  << " yaw=" << editorAt(0)->yaw << " scale=" << editorAt(0)->scale << std::endl;
        break;
    }
    case 2: {
        SetWindowTextW(inspectorEdit(5), L"48.00");
        SetWindowTextW(inspectorEdit(6), L"10.00");
        SetWindowTextW(inspectorEdit(7), L"2.00");
        click(1040); int raise = studioBrush().mode;
        click(1041); int lower = studioBrush().mode;
        click(1042); int smooth = studioBrush().mode;
        click(1043); int flat = studioBrush().mode;
        click(1040);
        editorTap(window, 'B'); editorHandleInput(window);
        kg::Settings settings; settings.seed = 20261025; settings.biome = kg::Biome::Tropical;
        float h = static_cast<float>(kg::sampleHeight(-10.0, 0.0, settings));
        float view[16], proj[16]; int px = 0, py = 0; float depth = 0;
        editorCamera(view, proj, window.getWidth(), window.getHeight());
        editorProject(view, proj, -10.0f, h, 0.0f, window.getWidth(), window.getHeight(), px, py, depth);
        editorDrag(window, px, py, px + 24, py); editorHandleInput(window);
        std::cout << "[INSPECTOR] modes=" << raise << "," << lower << "," << smooth << "," << flat
                  << " brush=" << studioBrush().radius << " on=" << studioBrushOn()
                  << " cursor=" << studioCaptureCursor("F:/rawrxd/kartgib/evidence/studio_cursor.bmp")
                  << " pixel=" << px << "," << py << std::endl;
        renderer.requestEditorShot("gui_sculpt");
        break;
    }
    case 3:
        std::cout << "[INSPECTOR] height " << studioBaseY() << " -> " << studioMeshY() << std::endl;
        sunshineScene("transform 1 9 18 24 0 1");
        inspectorRefresh();
        { wchar_t text[32]{}; GetWindowTextW(xEdit, text, 32); std::wcout << L"[INSPECTOR] sunshine=" << text << std::endl; }
        click(1050); inspectorRefresh();
        { wchar_t text[32]{}, yaw[32]{}; GetWindowTextW(xEdit, text, 32); GetWindowTextW(inspectorEdit(3), yaw, 32);
          std::wcout << L"[INSPECTOR] undo=" << text << L" yaw=" << yaw << std::endl; }
        click(1051); inspectorRefresh();
        std::cout << "[INSPECTOR] redo x=" << editorAt(0)->x << std::endl;
        break;
    default: {
        bool saved = studioSaveProject(kDir);
        int child = reloadChild(studioMeshY(), editorAt(0)->x, studioBrush().radius, inspectorWidth(),
            editorAt(0)->yaw, editorAt(0)->scale);
        std::cout << "[INSPECTOR] save=" << saved << " reload=" << child << " width=" << inspectorWidth() << std::endl;
        editorMarkDone();
        return false;
    }
    }
    return true;
}
